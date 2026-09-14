from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pymongo.database import Database

from database.session import get_db

from ..rbac import require_roles
from ..repositories import PolicyRepository
from ..schemas import PolicyRequest, PolicyResponse

router = APIRouter(prefix="/api/policies", tags=["policies"])


def _to_response(row) -> PolicyResponse:
    return PolicyResponse(
        id=row.id,
        name=row.name,
        rule_type=row.rule_type,
        config=row.config_json,
        active=row.active,
    )


@router.get(
    "",
    response_model=list[PolicyResponse],
    dependencies=[Depends(require_roles("ADMIN"))],
)
def list_policies(
    db: Database = Depends(get_db),
) -> list[PolicyResponse]:
    """Policy Engine is ADMIN-only end to end (see section D of the
    fix pass) — reading policy configuration is itself sensitive
    (it reveals the security rules in force), so GET must be exactly
    as restricted as POST/PUT/DELETE, not merely 'any authenticated
    user'."""
    return [_to_response(row) for row in PolicyRepository(db).list_all()]


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def create_policy(
    payload: PolicyRequest,
    db: Database = Depends(get_db),
) -> PolicyResponse:
    row = PolicyRepository(db).create(
        payload.name,
        payload.rule_type,
        payload.config,
        payload.active,
    )
    return _to_response(row)


@router.put(
    "/{policy_id}",
    response_model=PolicyResponse,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def update_policy(
    policy_id: int,
    payload: PolicyRequest,
    db: Database = Depends(get_db),
) -> PolicyResponse:
    row = PolicyRepository(db).update(
        policy_id,
        payload.name,
        payload.rule_type,
        payload.config,
        payload.active,
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="policy not found",
        )
    return _to_response(row)


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def delete_policy(
    policy_id: int,
    db: Database = Depends(get_db),
) -> Response:
    deleted = PolicyRepository(db).delete(policy_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="policy not found",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)