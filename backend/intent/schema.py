"""
Cryptographic Intent Descriptor (CID) schema.

The CID is the structured, deterministic, verifiable authorization
descriptor that this project binds encryption keys to. It intentionally
contains no notion of human emotion or inferred intent — every field is
a concrete, checkable fact about the requested operation's context.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

Operation = Literal["encrypt", "decrypt", "read", "write", "share", "revoke"]

_REQUIRED_STRING_FIELDS = (
    "sender",
    "receiver",
    "purpose",
    "resource",
    "device_id",
    "session_id",
)


class CID(BaseModel):
    """Cryptographic Intent Descriptor.

    Required fields describe who is doing what, to what resource, from
    which device, in which session, and for how long that authorization
    is valid. Optional fields add organizational context and an
    extensibility escape hatch (`metadata`) for fields not yet defined
    without breaking canonicalization for existing CIDs.
    """

    model_config = ConfigDict(extra="forbid")

    sender: str
    receiver: str
    purpose: str
    resource: str
    operation: Operation
    device_id: str
    session_id: str
    valid_from: datetime
    valid_until: datetime

    classification: Optional[str] = None
    department: Optional[str] = None
    project: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @field_validator(*_REQUIRED_STRING_FIELDS, mode="before")
    @classmethod
    def _strip_strings(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("valid_from", "valid_until", mode="before")
    @classmethod
    def _assume_utc_if_naive(cls, value: Any) -> Any:
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @model_validator(mode="after")
    def _check_semantics(self) -> "CID":
        for field_name in _REQUIRED_STRING_FIELDS:
            if not getattr(self, field_name):
                raise ValueError(f"'{field_name}' must not be empty")
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be strictly after valid_from")
        return self
