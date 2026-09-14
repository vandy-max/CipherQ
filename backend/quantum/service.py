"""
Injectable service wrapper around the BB84 simulation.

`api/` should depend on this class (constructor-injected), not on the
free functions in `bb84.py` directly — keeps routes swappable/mockable
in tests without touching the physics module.
"""
from __future__ import annotations

from .bb84 import (
    DEFAULT_N_QUBITS,
    DEFAULT_QBER_ABORT_THRESHOLD,
    BB84Result,
    quantum_backend_info,
    simulate_bb84,
)


class QuantumKeyExchangeService:
    """Facade over the BB84 simulation with configurable defaults."""

    def __init__(
        self,
        n_qubits: int = DEFAULT_N_QUBITS,
        qber_abort_threshold: float = DEFAULT_QBER_ABORT_THRESHOLD,
    ) -> None:
        self._n_qubits = n_qubits
        self._qber_abort_threshold = qber_abort_threshold

    def generate_shared_key(
        self,
        eavesdrop_prob: float = 0.0,
        n_qubits: int | None = None,
    ) -> BB84Result:
        """Run a fresh BB84 session and return the shared secret plus
        protocol telemetry. Callers MUST check `session_aborted` before
        using `quantum_key_hex` / `key_bytes` for anything."""
        return simulate_bb84(
            n_qubits=n_qubits or self._n_qubits,
            eavesdrop_prob=eavesdrop_prob,
            qber_abort_threshold=self._qber_abort_threshold,
        )

    def backend_info(self) -> dict:
        return quantum_backend_info()
