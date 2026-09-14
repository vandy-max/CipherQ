"""
Face authentication — identity verification only.

The reference project ran face-api.js's *expression* model
(`faceExpressionNet`) and folded the detected emotion directly into
key derivation. It never actually verified identity — there was no
descriptor/embedding comparison against an enrolled face at all.

This service does the part the reference project didn't: it compares
a probe face descriptor (a 128-d embedding, produced client-side by
face-api.js's `faceRecognitionNet` — the model-loading plumbing is the
same shape as the reference project's, just a different net) against
the user's enrolled descriptor, and produces a verified/confidence
result. That result feeds `policy.RiskFactors.face_confidence` only —
never key derivation, never a CID field.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol, Sequence

DESCRIPTOR_LENGTH = 128
# face-api.js's documentation recommends ~0.6 Euclidean distance as
# the match/no-match threshold for its 128-d descriptors.
DISTANCE_THRESHOLD = 0.6


class FaceDescriptorRepository(Protocol):
    def get_enrolled_descriptor(self, user_id: int) -> Sequence[float] | None: ...
    def save_enrolled_descriptor(self, user_id: int, descriptor: Sequence[float]) -> None: ...


class InMemoryFaceDescriptorRepository:
    """Reference/test implementation only — not for production use."""

    def __init__(self) -> None:
        self._descriptors: dict[int, tuple[float, ...]] = {}

    def get_enrolled_descriptor(self, user_id: int) -> Sequence[float] | None:
        return self._descriptors.get(user_id)

    def save_enrolled_descriptor(self, user_id: int, descriptor: Sequence[float]) -> None:
        self._descriptors[user_id] = tuple(descriptor)


@dataclass(frozen=True)
class FaceVerificationResult:
    verified: bool
    confidence: float  # 0.0-1.0, higher = more confident match
    distance: float


def _euclidean_distance(a: Sequence[float], b: Sequence[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


class FaceAuthService:
    def __init__(
        self,
        repository: FaceDescriptorRepository,
        distance_threshold: float = DISTANCE_THRESHOLD,
    ) -> None:
        self._repository = repository
        self._distance_threshold = distance_threshold

    def enroll(self, user_id: int, descriptor: Sequence[float]) -> None:
        self._validate_descriptor(descriptor)
        self._repository.save_enrolled_descriptor(user_id, descriptor)

    def is_enrolled(self, user_id: int) -> bool:
        return self._repository.get_enrolled_descriptor(user_id) is not None

    def verify(self, user_id: int, probe_descriptor: Sequence[float]) -> FaceVerificationResult:
        self._validate_descriptor(probe_descriptor)
        enrolled = self._repository.get_enrolled_descriptor(user_id)
        if enrolled is None:
            return FaceVerificationResult(verified=False, confidence=0.0, distance=math.inf)

        distance = _euclidean_distance(enrolled, probe_descriptor)
        confidence = max(0.0, 1.0 - (distance / (2 * self._distance_threshold)))
        verified = distance <= self._distance_threshold
        return FaceVerificationResult(
            verified=verified,
            confidence=round(confidence, 4),
            distance=round(distance, 4),
        )

    @staticmethod
    def _validate_descriptor(descriptor: Sequence[float]) -> None:
        if len(descriptor) != DESCRIPTOR_LENGTH:
            raise ValueError(
                f"face descriptor must have length {DESCRIPTOR_LENGTH}, got {len(descriptor)}"
            )
