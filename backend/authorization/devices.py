"""
Device validity state.

A device is valid until explicitly revoked. Devices are not required
to be pre-registered: the first time a `device_id` is seen it is
implicitly treated as a valid, known device (matches the existing CID
contract, where `device_id` is just a caller-supplied string) — but
once revoked, it stays revoked until an administrator re-authorizes it
by calling `unrevoke`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class DeviceStatus:
    device_id: str
    revoked: bool = False


class DeviceRepository(Protocol):
    def get_status(self, device_id: str) -> DeviceStatus: ...
    def revoke(self, device_id: str) -> DeviceStatus: ...
    def unrevoke(self, device_id: str) -> DeviceStatus: ...


class InMemoryDeviceRepository:
    """Reference/test implementation only — not for production use."""

    def __init__(self) -> None:
        self._devices: dict[str, DeviceStatus] = {}

    def get_status(self, device_id: str) -> DeviceStatus:
        return self._devices.setdefault(device_id, DeviceStatus(device_id=device_id))

    def revoke(self, device_id: str) -> DeviceStatus:
        status = self.get_status(device_id)
        status.revoked = True
        return status

    def unrevoke(self, device_id: str) -> DeviceStatus:
        status = self.get_status(device_id)
        status.revoked = False
        return status
