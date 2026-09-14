from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.database import Database

from audit.events import AuditEvent
from audit.service import AuditLogService
from database.session import get_db
from intent.lifecycle import IntentState, InvalidTransitionError
from intent.schema import CID
from intent.validation import IntentValidationService

from ..dependencies import (
    get_audit_service, get_current_user, get_intent_validation_service,
    get_device_repository, get_session_repository, get_monitoring_service,
)
from ..rbac import ADMIN, USER_LEVEL_2, is_admin_role, require_owner_or_admin
from ..repositories import IntentRepository, MongoUserRepository
from monitoring.state import MonitoringStatus

from ..schemas import (
    CIDRequest,
    CreateIntentRequest,
    DeviceCheckResponse,
    IdentityCheckResponse,
    IntentResolveResponse,
    IntentResponse,
    IntentSummaryResponse,
    IntentValidationResponse,
    PolicyOutcomeResponse,
    SessionCheckResponse,
    TransitionIntentRequest,
    ValidateIntentRequest,
)

router = APIRouter(prefix="/api/intent", tags=["intent"])

# States a caller may request directly through this endpoint. `USED`
# is deliberately excluded: it is reached exclusively as a side effect
# of a *successful* `/api/encrypt` call (see api/routers/encryption.py),
# never through a direct lifecycle-transition request. Allowing it here
# would let a caller mark an intent "used" without ever having actually
# encrypted anything under it, defeating the one-shot-per-approval
# guarantee and the "no manual lifecycle edits" requirement.
_DIRECTLY_TRANSITIONABLE_STATES = frozenset(
    {
        IntentState.APPROVED,
        IntentState.REJECTED,
        IntentState.EXPIRED,
        IntentState.ARCHIVED,
        IntentState.DESTROYED,
    }
)

_INTENT_TRANSITION_EVENT = {
    IntentState.APPROVED: AuditEvent.INTENT_APPROVED,
    IntentState.REJECTED: AuditEvent.INTENT_REJECTED,
    IntentState.EXPIRED: AuditEvent.INTENT_EXPIRED,
    IntentState.ARCHIVED: AuditEvent.INTENT_ARCHIVED,
    IntentState.DESTROYED: AuditEvent.INTENT_DESTROYED,
    IntentState.USED: AuditEvent.INTENT_USED,
}


@router.get("", response_model=list[IntentSummaryResponse])
def list_intents(
    lifecycle_state: str | None = None,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
) -> list[IntentSummaryResponse]:
    """List intents — backs both the Intent History page and the
    Admin Dashboard's Intent Approval/Management section.

    Role-scoped: a USER_LEVEL_1 caller only ever sees intents they
    created (its own history — never someone else's). A USER_LEVEL_2
    or ADMIN caller sees every intent, since discovering *other users'*
    DRAFT intents that need review is the entire point of the approval
    workflow (see separation-of-duties in `transition_intent` below).

    Each row is enriched with the resource/operation/purpose from the
    intent's own recorded CID and the creator's username/role, so a
    reviewer can actually see what they're approving/rejecting without
    a second lookup — reused from `IntentRepository.get_current_cid`
    and `MongoUserRepository`, never invented.
    """
    state_filter: IntentState | None = None
    if lifecycle_state is not None:
        try:
            state_filter = IntentState(lifecycle_state)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, f"unknown lifecycle state '{lifecycle_state}'"
            ) from exc

    repo = IntentRepository(db)
    user_repo = MongoUserRepository(db)
    owner_scope = None if user.role in (USER_LEVEL_2, ADMIN) else user.user_id
    rows = repo.list_all(created_by=owner_scope, lifecycle_state=state_filter)

    user_cache: dict[int, object] = {}

    def _creator(user_id: int):
        if user_id not in user_cache:
            user_cache[user_id] = user_repo.get_by_id(user_id)
        return user_cache[user_id]

    summaries: list[IntentSummaryResponse] = []
    for row in rows:
        creator = _creator(row.created_by)
        resource = operation = purpose = None
        try:
            cid = repo.get_current_cid(row)
            resource = cid.resource
            operation = cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation)
            purpose = cid.purpose
        except ValueError:
            # No version doc found for this row (shouldn't happen in
            # practice, since every intent is created with a version)
            # — degrade gracefully rather than failing the whole list.
            pass

        summaries.append(
            IntentSummaryResponse(
                intent_id=row.id,
                intent_hash=row.canonical_hash,
                lifecycle_state=row.lifecycle_state.value,
                created_by=row.created_by,
                created_by_username=creator.username if creator else None,
                created_by_role=creator.role if creator else None,
                created_at=row.created_at,
                resource=resource,
                operation=operation,
                purpose=purpose,
            )
        )
    return summaries


@router.get("/by-hash/{intent_hash}", response_model=IntentResolveResponse)
def resolve_intent_by_hash(
    intent_hash: str,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
) -> IntentResolveResponse:
    """Fix pass section F — the "Intent Hash -> Encryption" lookup
    flow. A user with an approved intent copies its hash and pastes it
    here (via the Encryption page); the backend looks up the
    AUTHORITATIVE stored intent and returns everything the caller
    needs to encrypt under it — crucially including `valid_from` /
    `valid_until`, which come exclusively from the intent's own
    recorded CID (see `IntentRepository.get_current_cid`), never from
    anything the browser supplies. The Encryption page must never let
    a user hand-type a validity window for an already-created intent;
    this endpoint is what makes that unnecessary.

    Only the intent's owner or an ADMIN may resolve it this way — a
    hash alone does not grant visibility into someone else's intent
    context. This endpoint never mutates lifecycle state and never
    performs any policy/risk/authorization evaluation; it is read-only
    detail lookup. The actual authorization decision (device, session,
    lifecycle, policy, risk) happens later, when `/api/encrypt` is
    called with this data — this endpoint just resolves what to show
    and what to submit.
    """
    repo = IntentRepository(db)
    intent_row = repo.get_by_hash(intent_hash)
    if intent_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no intent found for that hash")
    require_owner_or_admin(user, intent_row.created_by, action="resolve")

    try:
        cid = repo.get_current_cid(intent_row)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    cid_request = CIDRequest(**cid.model_dump())

    return IntentResolveResponse(
        intent_id=intent_row.id,
        intent_hash=intent_row.canonical_hash,
        lifecycle_state=intent_row.lifecycle_state.value,
        created_by=intent_row.created_by,
        created_at=intent_row.created_at,
        sender=cid.sender,
        receiver=cid.receiver,
        purpose=cid.purpose,
        resource=cid.resource,
        operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
        device_id=cid.device_id,
        session_id=cid.session_id,
        valid_from=cid.valid_from,
        valid_until=cid.valid_until,
        classification=cid.classification,
        department=cid.department,
        project=cid.project,
        cid=cid_request,
    )


@router.post("", response_model=IntentResponse, status_code=status.HTTP_201_CREATED)
def create_intent(
    payload: CreateIntentRequest,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
    audit: AuditLogService = Depends(get_audit_service),
    session_repo=Depends(get_session_repository),
    device_repo=Depends(get_device_repository),
    monitoring_service=Depends(get_monitoring_service),
    validation_service: IntentValidationService = Depends(get_intent_validation_service),
) -> IntentResponse:
    try:
        cid = CID(**payload.cid.model_dump())
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    # Intent creation is protected by the same live-monitoring gate as
    # crypto. ACTIVE and WARNING may continue; REAUTH_REQUIRED/REVOKED
    # must stop before an Intent document is ever created.
    if (
        hasattr(session_repo, "get")
        and hasattr(device_repo, "get_status")
        and hasattr(monitoring_service, "get_by_session")
    ):
        session_state = session_repo.get(cid.session_id)
        if session_state is None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "the supplied session does not exist; use the current authenticated session",
            )
        if session_state.user_id != user.user_id:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "the supplied session does not belong to the current user",
            )
        if session_state.revoked:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "session is revoked; reauthenticate before creating an intent",
            )
        current_session_id = getattr(user, "session_id", None)
        if current_session_id and cid.session_id != current_session_id:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "intent session must match the current authenticated session",
            )
        device_status = device_repo.get_status(cid.device_id)
        if device_status is None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "the supplied device does not exist; use the current authorized device",
            )
        # `DeviceStatus` (authorization/devices.py) intentionally only
        # knows device_id/revoked — it has no `user_id` field. Ownership
        # is a separate, API-layer concern tracked by
        # `MongoDeviceRepository.get_owner` (the same repository/method
        # session establishment uses to claim ownership — see
        # api/routers/authorization.py). Looking for `user_id` directly
        # on `device_status` here always raised AttributeError, which
        # made every intent-creation request fail with a 500 — the root
        # cause of "cryptography failed" further down the encrypt flow.
        if hasattr(device_repo, "get_owner"):
            existing_device_owner = device_repo.get_owner(cid.device_id)
            if existing_device_owner is not None and existing_device_owner != user.user_id and not is_admin_role(user.role):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "the supplied device does not belong to the current user",
                )
        if device_status.revoked:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "session is blocked because the device is revoked; administrator recovery is required",
            )
        monitoring_record = monitoring_service.get_by_session(cid.session_id)
        if monitoring_record is None or monitoring_record.stopped:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "session is removed or continuous monitoring is not active; reauthenticate before creating an intent",
            )
        monitoring_snapshot = monitoring_service.refresh(monitoring_record.monitoring_session_id)
        if monitoring_snapshot.status in (MonitoringStatus.REAUTH_REQUIRED, MonitoringStatus.REVOKED):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "session is removed or requires reauthentication; create the intent only after fresh reauthentication",
            )

    repo = IntentRepository(db)
    intent_row = repo.create(
        cid, author=user.username, reason=payload.reason, created_by=user.user_id
    )
    audit.record(
        AuditEvent.INTENT_CREATED,
        "success",
        user_id=user.user_id,
        intent_hash=intent_row.canonical_hash,
        device_id=cid.device_id,
        session_id=cid.session_id,
        resource=cid.resource,
        operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
    )

    # ADMIN intents do not use the ordinary "wait for an admin approval"
    # UX because the creator is already the administrative authority.
    # For the low-risk case only, perform the same server-side validation
    # used by the approval endpoint and immediately move DRAFT -> APPROVED.
    # This is deliberately restricted to an exact zero risk score and a
    # fully eligible validation result; a non-zero-risk Admin intent remains
    # a DRAFT and cannot silently enter the crypto path.
    lifecycle_state = intent_row.lifecycle_state.value
    if user.role == ADMIN:
        validation_result = validation_service.validate(
            cid, current_lifecycle=IntentState.DRAFT, requesting_user_role=user.role
        )
        if validation_result.approval_eligible and validation_result.risk.score == 0:
            intent_row = repo.transition(intent_row, IntentState.APPROVED)
            lifecycle_state = intent_row.lifecycle_state.value
            audit.record(
                AuditEvent.INTENT_APPROVED,
                "success",
                user_id=user.user_id,
                intent_hash=intent_row.canonical_hash,
                risk=validation_result.risk.level.value,
                reason="automatic approval for ADMIN-created zero-risk intent",
            )

    return IntentResponse(
        intent_id=intent_row.id,
        version_number=1,
        intent_hash=intent_row.canonical_hash,
        lifecycle_state=lifecycle_state,
    )


@router.post("/validate", response_model=IntentValidationResponse)
def validate_intent(
    payload: ValidateIntentRequest,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
    validation_service: IntentValidationService = Depends(get_intent_validation_service),
    audit: AuditLogService = Depends(get_audit_service),
) -> IntentValidationResponse:
    """Automatic intent validation: structure -> canonicalization ->
    SHA-256 hash -> policy -> risk -> identity -> device -> session ->
    approval eligibility. Purely a report — never creates, approves,
    or mutates an intent, and never touches the crypto path. If
    `intent_id` is given, its CURRENT lifecycle state is loaded and
    reflected in the result; otherwise validation is run as if for a
    not-yet-created (Draft) intent.
    """
    try:
        cid = CID(**payload.cid.model_dump())
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    current_lifecycle = IntentState.DRAFT
    if payload.intent_id is not None:
        intent_repo = IntentRepository(db)
        intent_row = intent_repo.get_by_id(payload.intent_id)
        if intent_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "intent not found")
        require_owner_or_admin(user, intent_row.created_by, action="validate")
        current_lifecycle = intent_row.lifecycle_state

    result = validation_service.validate(
        cid, current_lifecycle=current_lifecycle, requesting_user_role=user.role
    )
    audit.record(
        AuditEvent.INTENT_VALIDATED,
        "success" if result.valid else "invalid",
        user_id=user.user_id,
        intent_hash=result.intent_hash,
        device_id=cid.device_id,
        session_id=cid.session_id,
        resource=cid.resource,
        operation=cid.operation.value if hasattr(cid.operation, "value") else str(cid.operation),
        risk=result.risk.level.value,
        reason=result.reason,
    )

    return IntentValidationResponse(
        valid=result.valid,
        canonicalized_intent=result.canonicalized_intent,
        intent_hash=result.intent_hash,
        resource=result.resource,
        operation=result.operation,
        purpose=result.purpose,
        valid_from=result.valid_from,
        valid_until=result.valid_until,
        policy_passed=result.policy_result.passed,
        policy_outcomes=[
            PolicyOutcomeResponse(rule_name=o.rule_name, passed=o.passed, reason=o.reason)
            for o in result.policy_result.outcomes
        ],
        risk_score=result.risk.score,
        risk_level=result.risk.level.value,
        identity=IdentityCheckResponse(
            checked=result.identity.checked,
            verified=result.identity.verified,
            confidence=result.identity.confidence,
            reason=result.identity.reason,
        ),
        device=DeviceCheckResponse(
            device_id=result.device.device_id, revoked=result.device.revoked
        ),
        session=SessionCheckResponse(
            session_id=result.session.session_id,
            known=result.session.known,
            valid=result.session.valid,
            reason=result.session.reason,
        ),
        current_lifecycle=result.current_lifecycle.value,
        approval_eligible=result.approval_eligible,
        reason=result.reason,
    )


@router.post("/{intent_id}/transition", response_model=IntentResponse)
def transition_intent(
    intent_id: int,
    payload: TransitionIntentRequest,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
    audit: AuditLogService = Depends(get_audit_service),
    validation_service: IntentValidationService = Depends(get_intent_validation_service),
) -> IntentResponse:
    """The ONLY authorized way an intent's lifecycle state changes as
    the result of a direct request (as opposed to a side effect of a
    successful encryption). Backed entirely by `intent.lifecycle`'s
    state machine plus, for DRAFT -> APPROVED specifically, the same
    automatic-validation pipeline (`IntentValidationService`) that
    `/api/intent/validate` reports on — approval is refused unless
    `approval_eligible` comes back true for the intent's OWN recorded
    CID. There is no path in this codebase that lets a caller set
    `lifecycle_state` directly; this endpoint is it, and it never skips
    the eligibility check.
    """
    repo = IntentRepository(db)
    intent_row = repo.get_by_id(intent_id)
    if intent_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "intent not found")

    try:
        target = IntentState(payload.target_state)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"unknown lifecycle state '{payload.target_state}'"
        ) from exc

    # Approval is deliberately NOT gated by ownership here: a
    # USER_LEVEL_2/ADMIN reviewer approving someone ELSE's intent is
    # the whole point of separation of duties (see the dedicated
    # approver-privilege check below, once `target is APPROVED`).
    # Rejection follows the same reviewer model as approval — a
    # reviewer must be able to reject someone else's draft, not just
    # their own — but ALSO allows the intent's own creator to
    # self-withdraw a draft they no longer want reviewed (unlike
    # self-approval, self-rejection isn't a privilege-escalation risk).
    # Every other transition (expired/archived/destroyed) keeps the
    # original owner-or-admin restriction.
    if target is IntentState.REJECTED:
        is_owner = intent_row.created_by == user.user_id
        is_reviewer = user.role in (USER_LEVEL_2, ADMIN)
        if not (is_owner or is_reviewer):
            reason = "rejecting requires being the intent's owner or holding USER_LEVEL_2/ADMIN privilege"
            audit.record(
                AuditEvent.INTENT_REJECTED,
                "rejected",
                user_id=user.user_id,
                intent_hash=intent_row.canonical_hash,
                reason=reason,
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, reason)
    elif target is not IntentState.APPROVED:
        require_owner_or_admin(user, intent_row.created_by, action="transition")

    if target not in _DIRECTLY_TRANSITIONABLE_STATES:
        audit.record(
            AuditEvent.INTENT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=intent_row.canonical_hash,
            reason=f"'{target.value}' is not directly reachable",
        )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"'{target.value}' cannot be requested directly; it is only reached as the "
            "result of another operation (e.g. a successful encryption)",
        )

    # -- Approval gate: DRAFT -> APPROVED must pass the SAME
    # validation pipeline (policy, risk, identity, device, session,
    # validity window) that `/api/intent/validate` reports on, run
    # against the intent's own recorded CID. This is what makes
    # approval an "authorized approval workflow" rather than a bare
    # state flip: nothing about this request can force approval_eligible
    # to be true. --
    if target is IntentState.APPROVED:
        # -- Separation of duties (requirement: a user must never be
        # able to create a sensitive intent and then approve their own
        # intent). Enforced here, server-side, independent of any
        # configured `role_matching` policy: approving requires at
        # least USER_LEVEL_2 privilege, AND the approver must not be
        # the intent's own creator unless they hold ADMIN. A
        # USER_LEVEL_1 can never approve anything, including their own
        # drafts; a USER_LEVEL_2 may approve other users' intents but
        # not their own; only ADMIN may approve its own intent (e.g.
        # emergency/break-glass), and every approval is still subject
        # to the eligibility pipeline below regardless of who runs it.
        approver_role = user.role
        is_self = intent_row.created_by == user.user_id
        if approver_role not in (USER_LEVEL_2, ADMIN) or (is_self and not is_admin_role(approver_role)):
            reason = (
                "approver must hold USER_LEVEL_2 or ADMIN privilege"
                if approver_role not in (USER_LEVEL_2, ADMIN)
                else "separation of duties: a user cannot approve their own intent"
            )
            audit.record(
                AuditEvent.INTENT_REJECTED,
                "rejected",
                user_id=user.user_id,
                intent_hash=intent_row.canonical_hash,
                reason=reason,
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, reason)

        cid = repo.get_current_cid(intent_row)
        validation_result = validation_service.validate(
            cid, current_lifecycle=intent_row.lifecycle_state, requesting_user_role=user.role
        )
        if not validation_result.approval_eligible:
            audit.record(
                AuditEvent.INTENT_REJECTED,
                "rejected",
                user_id=user.user_id,
                intent_hash=intent_row.canonical_hash,
                risk=validation_result.risk.level.value,
                reason=validation_result.reason,
            )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"intent {intent_id} is not approval-eligible: {validation_result.reason}",
            )

    try:
        updated = repo.transition(intent_row, target)
    except InvalidTransitionError as exc:
        audit.record(
            AuditEvent.INTENT_REJECTED,
            "rejected",
            user_id=user.user_id,
            intent_hash=intent_row.canonical_hash,
            reason=str(exc),
        )
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    audit.record(
        _INTENT_TRANSITION_EVENT.get(target, AuditEvent.INTENT_VALIDATED),
        "success",
        user_id=user.user_id,
        intent_hash=updated.canonical_hash,
    )
    return IntentResponse(
        intent_id=updated.id,
        version_number=repo.current_version_number(updated.id),
        intent_hash=updated.canonical_hash,
        lifecycle_state=updated.lifecycle_state.value,
    )
