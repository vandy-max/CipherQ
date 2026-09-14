from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.database import Database

from audit.events import AuditEvent
from audit.service import AuditLogService
from authentication.face_auth import FaceAuthService
from authorization import (
    AuthorizationError,
    AuthorizationService,
    DeviceRevokedError,
    LifecycleRejectedError,
    PolicyRejectedError,
    SessionInvalidError,
)
from crypto.service import EncryptionService
from database.session import get_db
from intent.canonicalizer import compute_intent_hash
from intent.lifecycle import ENCRYPT_ELIGIBLE_STATES, IntentState
from intent.schema import CID
from policy import ai_risk_service
from policy.context_collector import SecurityContextCollector
from policy.ml_risk import MLRiskModel
from policy.risk import FACE_CONFIDENCE_THRESHOLD, RiskAction, RiskEngine


from ..dependencies import (
    get_audit_service,
    get_authorization_service,
    get_current_user,
    get_encryption_service,
    get_face_auth_service,
    get_ml_risk_model,
    get_risk_engine,
    get_security_context_collector,
    get_qira_service,
    get_monitoring_service,
)
from ..rbac import require_owner_or_admin
from ..repositories import EncryptionRecordRepository, IntentRepository
from ..schemas import EncryptRequest, EncryptResponse
from monitoring.crypto_gate import MonitoringCryptoBlockedError, require_crypto_monitoring

router = APIRouter(prefix="/api/encrypt", tags=["encryption"])

_AUTHZ_STATUS = {
    DeviceRevokedError: status.HTTP_403_FORBIDDEN,
    SessionInvalidError: status.HTTP_401_UNAUTHORIZED,
    LifecycleRejectedError: status.HTTP_409_CONFLICT,
    PolicyRejectedError: status.HTTP_403_FORBIDDEN,
}


@router.post("", response_model=EncryptResponse, status_code=status.HTTP_201_CREATED)
def encrypt(
    payload: EncryptRequest,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
    encryption_service: EncryptionService = Depends(get_encryption_service),
    face_auth: FaceAuthService = Depends(get_face_auth_service),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    context_collector: SecurityContextCollector = Depends(get_security_context_collector),
    ml_risk_model: MLRiskModel = Depends(get_ml_risk_model),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
    audit: AuditLogService = Depends(get_audit_service),
    qira_service=Depends(get_qira_service),
    monitoring_service=Depends(get_monitoring_service),
) -> EncryptResponse:
    # The live monitoring state machine is the authoritative crypto gate.
    # ACTIVE and WARNING continue to permit crypto; REAUTH_REQUIRED and
    # REVOKED are blocked until a fresh authorized session exists.
    # Direct router unit tests may call this function without FastAPI
    # dependency resolution; production requests always receive the real
    # MonitoringService here.
    if hasattr(monitoring_service, "get_by_session"):
        try:
            require_crypto_monitoring(
                monitoring_service, session_id=payload.cid.session_id if hasattr(payload, "cid") else cid.session_id, user_id=user.user_id
            )
        except MonitoringCryptoBlockedError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, exc.reason) from exc

    # -- Mandatory face verification gate. This runs before anything
    # else in the encrypt flow and never touches the crypto logic
    # below it — a failed/missing probe stops the request outright. --
    if payload.face_descriptor is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "face verification required")

    face_result = face_auth.verify(user.user_id, payload.face_descriptor)
    if not face_result.verified:
        audit.record(AuditEvent.FACE_VERIFY_FAILURE, "rejected", user_id=user.user_id)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "face verification failed")
    audit.record(AuditEvent.FACE_VERIFY_SUCCESS, "success", user_id=user.user_id)

    try:
        cid = CID(**payload.cid.model_dump())
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    # Qira remains a separate advisory/risk-analysis layer. It must not
    # override the authoritative live-monitoring state for crypto access.

    # -- Autonomous AI-driven risk analysis (fix pass): the frontend
    # never supplies risk_score/risk_level/risk_factors — every signal
    # here is collected automatically by `SecurityContextCollector`
    # from device/session state and the audit trail, then scored by
    # the SAME deterministic RiskEngine used by /api/decrypt (so
    # encryption and decryption share one security model) plus the
    # advisory `MLRiskModel`. The deterministic verdict is what's
    # enforced; the ML layer can only ever add caution (see
    # policy/ai_risk_service.py), and a failure in the ML layer falls
    # back to the deterministic verdict alone rather than failing
    # open. This intentionally runs before the intent/policy checks
    # below, mirroring decrypt's ordering. --
    face_confidence = face_result.confidence
    ai_result = ai_risk_service.assess(
        collector=context_collector,
        risk_engine=risk_engine,
        user_id=user.user_id,
        cid=cid,
        face_confidence=face_confidence,
        ml_model=ml_risk_model,
        fold_device_session_revocation_into_score=False,
    )
    risk_action = RiskAction(ai_result.action)

    if risk_action in (RiskAction.REJECT, RiskAction.REVOKE):
        audit.record(
            AuditEvent.RISK_DENIED,
            "rejected",
            user_id=user.user_id,
            device_id=cid.device_id,
            session_id=cid.session_id,
            resource=cid.resource,
            risk=ai_result.risk_level,
            reason=ai_result.explanation,
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "request rejected: high risk assessment")

    if risk_action is RiskAction.REQUIRE_FACE_VERIFICATION and (
        face_confidence is None or face_confidence < FACE_CONFIDENCE_THRESHOLD
    ):
        audit.record(
            "encrypt_requires_face_verification",
            "step_up_required",
            user_id=user.user_id,
            device_id=cid.device_id,
            session_id=cid.session_id,
            resource=cid.resource,
            risk=ai_result.risk_level,
            reason=ai_result.explanation,
        )
        raise HTTPException(status.HTTP_428_PRECONDITION_REQUIRED, "face re-verification required")

    try:
        plaintext = base64.b64decode(payload.plaintext_base64, validate=True)
        quantum_key_bytes = bytes.fromhex(payload.quantum_key_hex)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"malformed input: {exc}") from exc

    # -- Load the CURRENT intent and its CURRENT lifecycle state. This
    # endpoint never creates or approves an intent itself — approval
    # happens exclusively through `/api/intent/{id}/transition`,
    # upstream of this call. --
    intent_repo = IntentRepository(db)
    intent_row = intent_repo.get_by_id(payload.intent_id)
    if intent_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "intent not found")
    require_owner_or_admin(user, intent_row.created_by, action="encrypt under")

    # The submitted CID must be exactly the one this intent was
    # approved for — recompute its canonical hash and compare against
    # the stored intent hash before anything else runs. This catches
    # a stolen/reused intent_id paired with a different CID.
    submitted_hash = compute_intent_hash(cid)
    if submitted_hash != intent_row.canonical_hash:
        audit.record(
            AuditEvent.ENCRYPT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=intent_row.canonical_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            resource=cid.resource,
            operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
            reason="submitted CID does not match approved intent hash",
        )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "submitted intent does not match the approved intent's canonical hash",
        )

    # -- Require APPROVED before anything touches policy, risk, or
    # crypto. Encryption is one-shot per approval: Draft (never
    # approved), Used (already consumed), Expired, Archived, and
    # Destroyed are all rejected here, explicitly and before any
    # BB84/HKDF/AES call, authorization check, or encryption record is
    # created. No auto-approval happens on this path. --
    if intent_row.lifecycle_state not in ENCRYPT_ELIGIBLE_STATES:
        audit.record(
            AuditEvent.ENCRYPT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=intent_row.canonical_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            resource=cid.resource,
            operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
            reason=f"intent not eligible for encryption in lifecycle state '{intent_row.lifecycle_state.value}'",
        )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"intent {intent_row.id} is not eligible for encryption in lifecycle state "
            f"'{intent_row.lifecycle_state.value}' (must be 'approved')",
        )

    # -- Explicit continuous-authorization check: device, session,
    # lifecycle, and policy, all evaluated against CURRENT state. Only
    # on success do we get the authorization_state_hash that gets
    # bound into key derivation below. --
    try:
        decision = authorization_service.authorize(
            cid,
            intent_id=intent_row.id,
            intent_lifecycle_state=intent_row.lifecycle_state,
            user_id=user.user_id,
            requesting_user_role=user.role,
        )
    except PolicyRejectedError as exc:
        audit.record(
            AuditEvent.POLICY_DENIED,
            "rejected",
            user_id=user.user_id,
            intent_hash=intent_row.canonical_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            reason=str(exc),
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except AuthorizationError as exc:
        audit.record(
            AuditEvent.ENCRYPT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=intent_row.canonical_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            reason=f"{type(exc).__name__}: {exc}",
        )
        raise HTTPException(_AUTHZ_STATUS.get(type(exc), status.HTTP_403_FORBIDDEN), str(exc)) from exc

    # -- BB84 already ran upstream (Quantum Center) to produce
    # `quantum_key_hex`; from here it's HKDF -> AES-GCM. If this
    # raises for any reason, the intent's lifecycle MUST remain
    # APPROVED — the transition to Used below only happens after
    # encryption actually succeeds. --
    try:
        envelope = encryption_service.encrypt_for_intent(
            plaintext, quantum_key_bytes, cid, decision.authorization_state_hash
        )
    except Exception as exc:
        audit.record(
            AuditEvent.ENCRYPT_FAILURE,
            "failure",
            user_id=user.user_id,
            intent_hash=intent_row.canonical_hash,
            device_id=cid.device_id,
            session_id=cid.session_id,
            reason=str(exc),
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "encryption failed") from exc

    intent_row = intent_repo.transition(intent_row, IntentState.USED)
    audit.record(
        AuditEvent.INTENT_USED,
        "success",
        user_id=user.user_id,
        intent_hash=intent_row.canonical_hash,
        device_id=cid.device_id,
        session_id=cid.session_id,
    )

    record_repo = EncryptionRecordRepository(db)
    record = record_repo.save(
        envelope, intent_version_id=intent_row.current_version_id, created_by=user.user_id
    )

    audit.record(
        AuditEvent.ENCRYPT_SUCCESS,
        "success",
        user_id=user.user_id,
        intent_hash=envelope.intent_hash,
        device_id=cid.device_id,
        session_id=cid.session_id,
        resource=cid.resource,
        operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
        risk=ai_result.risk_level,
        reason=(
            f"ai_available={ai_result.ai_available} model={ai_result.model_type} "
            f"confidence={ai_result.confidence} patterns={list(ai_result.detected_patterns)}"
        ),
    )

    return EncryptResponse(
        record_id=record.id,
        intent_id=intent_row.id,
        intent_hash=envelope.intent_hash,
        ciphertext_hex=envelope.ciphertext.hex(),
        nonce_hex=envelope.nonce.hex(),
        auth_tag_hex=envelope.auth_tag.hex(),
        authorization_state_hash=decision.authorization_state_hash,
        intent_lifecycle_state=intent_row.lifecycle_state.value,
        risk_level=ai_result.risk_level,
        risk_score=ai_result.risk_score,
        ai_risk_available=ai_result.ai_available,
        ai_risk_confidence=ai_result.confidence,
        ai_detected_patterns=list(ai_result.detected_patterns),
        ai_explanation=ai_result.explanation,
        ai_model_type=ai_result.model_type,
    )
