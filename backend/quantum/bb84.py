"""
BB84 quantum key distribution — real per-qubit Qiskit circuits, executed
in batched multi-qubit circuits.

Adapted from the reference project's `quantum_bb84.py`. The physics and
protocol logic are unchanged (they were already correct): each BB84
exchange (one bit, one preparation basis, one measurement basis) is a
genuine, independent qubit — not a vectorized classical stand-in. What
changed vs. the reference is packaging only — typed dataclass result
instead of a raw dict, module-level constants exposed for the
policy/config layer, no coupling to anything else in this codebase, and
(this revision) grouping multiple independent BB84 exchanges into a
single wider `QuantumCircuit` instead of one `QuantumCircuit(1)` per
exchange. The circuit *organization* changed; the BB84 protocol,
per-exchange physics, and total exchange count did not.

This module MUST remain independent: it must never import from
`intent`, `crypto`, `policy`, `audit`, or `database`. Its only output
is a shared secret (`quantum_key_hex`) plus protocol telemetry (QBER,
sifted bit count, abort flag). What happens to that secret afterward
(HKDF binding to an intent, etc.) is entirely the concern of `crypto/`.

BB84 basis convention:
    basis 0 = rectilinear / computational (Z) basis -> {|0>, |1>}
    basis 1 = diagonal (X) basis                     -> {|+>, |->}

Per-exchange protocol (one qubit, whether run alone or batched
alongside other independent exchanges in the same circuit):
    1. Alice picks a random bit and a random basis.
       - bit=1 -> apply X gate (|0> -> |1>)
       - basis=X -> apply H gate to rotate into the diagonal basis
    2. (Optional) Eve intercepts: measures in her own random basis,
       collapsing the qubit, then re-prepares and forwards a fresh
       qubit encoding what she measured. This is the real physical
       mechanism (wavefunction collapse / no-cloning) that introduces
       detectable errors when Eve's basis disagrees with Alice's — not
       injected classical noise.
    3. Bob picks a random basis; if it's the X basis he applies H
       before measuring in the computational basis.
    4. Bob's measured bit is read out of the circuit.

After all exchanges: Alice and Bob publicly compare bases (sifting),
keep only bits where bases matched, then sacrifice a public sample of
the sifted key to estimate the Quantum Bit Error Rate (QBER). QBER
above the abort threshold indicates eavesdropping and the key is
discarded.

Circuit batching:
    `simulate_bb84` still runs `n_qubits` independent BB84 exchanges
    (256 by default), but instead of one `QuantumCircuit(1)` per
    exchange, it groups them into wide circuits of up to
    `QUBITS_PER_CIRCUIT` (6) independent exchanges each — qubit i in a
    batch circuit is exchange i of that batch, with its own bit/basis,
    entirely unentangled from the other qubits in the same circuit.
    256 exchanges therefore become 42 six-qubit circuits plus one
    four-qubit remainder circuit. Eve's intercept-resend, when active,
    needs a second physical hop (Alice->Eve, then Eve->Bob) for
    whichever exchanges in a batch she intercepts, so those exchanges
    additionally run through a second, smaller batched circuit sized to
    just the intercepted subset.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

import numpy as np

try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator

    QISKIT_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without qiskit installed
    QISKIT_AVAILABLE = False

BASIS_Z = 0  # rectilinear / computational
BASIS_X = 1  # diagonal / Hadamard

DEFAULT_N_QUBITS = 256  # total independent BB84 exchanges in a session
DEFAULT_QBER_ABORT_THRESHOLD = 0.11  # 11%, standard BB84 abort threshold
QUBITS_PER_CIRCUIT = 6  # exchanges batched into a single QuantumCircuit

_simulator = AerSimulator() if QISKIT_AVAILABLE else None


def _require_qiskit() -> None:
    if not QISKIT_AVAILABLE:
        raise RuntimeError(
            "qiskit / qiskit-aer are not installed. Run: "
            "pip install qiskit qiskit-aer   (see backend/requirements.txt)"
        )


@dataclass(frozen=True)
class BB84Result:
    """Outcome of one full BB84 key-exchange session."""

    quantum_key_hex: str
    qber: float
    sifted_bits: int
    session_aborted: bool
    circuits_run: int
    backend: str
    total_exchanges: int = 0
    qubits_per_circuit: int = QUBITS_PER_CIRCUIT
    full_circuits: int = 0
    remainder_qubits: int = 0

    @property
    def key_bytes(self) -> bytes:
        """Raw shared-secret bytes. Never persist this — it is the
        quantum-derived key material that `crypto/` must run through
        HKDF before it is ever used for AES."""
        return bytes.fromhex(self.quantum_key_hex)


def build_bb84_circuit(alice_bit: int, alice_basis: int, bob_basis: int) -> "QuantumCircuit":
    """Build the 1-qubit circuit for one BB84 round. Exposed separately
    so it can be drawn/inspected (e.g. for the frontend's BB84
    Simulation page)."""
    _require_qiskit()
    qc = QuantumCircuit(1, 1, name="bb84_round")

    if alice_bit == 1:
        qc.x(0)
    if alice_basis == BASIS_X:
        qc.h(0)

    qc.barrier()

    if bob_basis == BASIS_X:
        qc.h(0)
    qc.measure(0, 0)
    return qc


def run_single_qubit(alice_bit: int, alice_basis: int, bob_basis: int) -> int:
    """Execute the 1-qubit circuit on Qiskit Aer and return the
    measured classical bit."""
    _require_qiskit()
    qc = build_bb84_circuit(alice_bit, alice_basis, bob_basis)
    result = _simulator.run(qc, shots=1, memory=True).result()
    return int(result.get_memory(qc)[0])


def build_bb84_batch_circuit(
    alice_bits: list[int], alice_bases: list[int], meas_bases: list[int]
) -> "QuantumCircuit":
    """Build one circuit holding several *independent* BB84 exchanges,
    one per qubit (qubit i <-> classical bit i <-> exchange i). Each
    qubit is prepared and measured on its own — there is no entangling
    gate between them, so this is exactly `len(alice_bits)` single-qubit
    BB84 rounds running side by side in one circuit object, not a
    multi-qubit encoding of shared data. Exposed separately so it can be
    drawn/inspected (e.g. for the frontend's BB84 Simulation page)."""
    _require_qiskit()
    n = len(alice_bits)
    qc = QuantumCircuit(n, n, name=f"bb84_batch_{n}")

    for i in range(n):
        if alice_bits[i] == 1:
            qc.x(i)
        if alice_bases[i] == BASIS_X:
            qc.h(i)

    qc.barrier()

    for i in range(n):
        if meas_bases[i] == BASIS_X:
            qc.h(i)
        qc.measure(i, i)

    return qc


def run_bb84_batch(
    alice_bits: list[int], alice_bases: list[int], meas_bases: list[int]
) -> list[int]:
    """Execute one batched circuit (width = len(alice_bits), up to
    QUBITS_PER_CIRCUIT) on Qiskit Aer and return the measured classical
    bits in the same order as the inputs."""
    _require_qiskit()
    n = len(alice_bits)
    qc = build_bb84_batch_circuit(alice_bits, alice_bases, meas_bases)
    result = _simulator.run(qc, shots=1, memory=True).result()
    # Qiskit's memory string has classical bit c[n-1] as the leftmost
    # character and c[0] as the rightmost, regardless of register width.
    memory = result.get_memory(qc)[0]
    return [int(memory[n - 1 - i]) for i in range(n)]


def simulate_bb84(
    n_qubits: int = DEFAULT_N_QUBITS,
    eavesdrop_prob: float = 0.0,
    qber_abort_threshold: float = DEFAULT_QBER_ABORT_THRESHOLD,
) -> BB84Result:
    """Run a full BB84 key exchange, one real qubit circuit at a time.

    `eavesdrop_prob`: probability [0, 1] that Eve intercepts any given
    qubit (intercept-resend attack). 0.0 = no eavesdropper.
    """
    _require_qiskit()
    if not 0.0 <= eavesdrop_prob <= 1.0:
        raise ValueError("eavesdrop_prob must be between 0.0 and 1.0")
    if n_qubits < 1:
        raise ValueError("n_qubits must be at least 1")

    rng = np.random.default_rng()

    alice_bits = rng.integers(0, 2, n_qubits)
    alice_bases = rng.integers(0, 2, n_qubits)
    bob_bases = rng.integers(0, 2, n_qubits)
    eve_intercepts = (
        rng.random(n_qubits) < eavesdrop_prob
        if eavesdrop_prob > 0
        else np.zeros(n_qubits, dtype=bool)
    )
    # Eve's own random basis per exchange — only meaningful where
    # eve_intercepts[i] is True, but drawn for every exchange up front
    # so batching doesn't change the RNG draw shape/order.
    eve_bases = rng.integers(0, 2, n_qubits)

    bob_bits = np.zeros(n_qubits, dtype=int)
    circuits_run = 0
    full_circuits = 0
    remainder_qubits = 0

    for batch_start in range(0, n_qubits, QUBITS_PER_CIRCUIT):
        batch_end = min(batch_start + QUBITS_PER_CIRCUIT, n_qubits)
        idx = list(range(batch_start, batch_end))
        batch_size = len(idx)

        b_alice_bits = [int(alice_bits[i]) for i in idx]
        b_alice_bases = [int(alice_bases[i]) for i in idx]
        b_intercepted = [bool(eve_intercepts[i]) for i in idx]
        b_eve_bases = [int(eve_bases[i]) for i in idx]
        b_bob_bases = [int(bob_bases[i]) for i in idx]

        if batch_size == QUBITS_PER_CIRCUIT:
            full_circuits += 1
        else:
            remainder_qubits = batch_size

        # Stage 1 (batched, up to QUBITS_PER_CIRCUIT qubits): Alice
        # transmits to whoever receives first — Eve, for exchanges she
        # intercepts in this batch, otherwise Bob directly.
        stage1_meas_bases = [
            b_eve_bases[j] if b_intercepted[j] else b_bob_bases[j]
            for j in range(batch_size)
        ]
        stage1_bits = run_bb84_batch(b_alice_bits, b_alice_bases, stage1_meas_bases)
        circuits_run += 1

        for j in range(batch_size):
            if not b_intercepted[j]:
                bob_bits[idx[j]] = stage1_bits[j]

        # Stage 2 (batched, sized to just the intercepted subset of
        # this batch, 0 to QUBITS_PER_CIRCUIT qubits): Eve re-prepares
        # what she measured and forwards it on to Bob. Genuine
        # measurement + re-preparation (wavefunction collapse /
        # no-cloning), not injected classical noise.
        intercepted_positions = [j for j in range(batch_size) if b_intercepted[j]]
        if intercepted_positions:
            s2_bits_in = [stage1_bits[j] for j in intercepted_positions]
            s2_bases_in = [b_eve_bases[j] for j in intercepted_positions]
            s2_meas_bases = [b_bob_bases[j] for j in intercepted_positions]
            stage2_bits = run_bb84_batch(s2_bits_in, s2_bases_in, s2_meas_bases)
            circuits_run += 1
            for k, j in enumerate(intercepted_positions):
                bob_bits[idx[j]] = stage2_bits[k]

    # -- Sifting: keep only rounds where Alice's and Bob's bases matched --
    matching = alice_bases == bob_bases
    sifted_alice = alice_bits[matching]
    sifted_bob = bob_bits[matching]

    if len(sifted_alice) == 0:
        return BB84Result(
            quantum_key_hex="",
            qber=1.0,
            sifted_bits=0,
            session_aborted=True,
            circuits_run=circuits_run,
            backend="qiskit-aer",
            total_exchanges=n_qubits,
            qubits_per_circuit=QUBITS_PER_CIRCUIT,
            full_circuits=full_circuits,
            remainder_qubits=remainder_qubits,
        )

    # -- Public QBER estimate: sacrifice ~20% of the sifted key --
    n_check = max(1, len(sifted_alice) // 5)
    check_idx = rng.choice(len(sifted_alice), size=n_check, replace=False)
    errors = int(np.sum(sifted_alice[check_idx] != sifted_bob[check_idx]))
    qber = errors / n_check

    remaining_mask = np.ones(len(sifted_alice), dtype=bool)
    remaining_mask[check_idx] = False
    final_key_bits = sifted_alice[remaining_mask]

    aborted = qber > qber_abort_threshold
    key_bytes = np.packbits(final_key_bits).tobytes() if len(final_key_bits) else b""
    # Stretch the raw sifted bits into a 256-bit key. This is *not* the
    # HKDF step required before AES use — it only turns variable-length
    # sifted bits into a fixed-length shared secret. `crypto/` is
    # responsible for running this through HKDF bound to an intent hash
    # before it is ever used to encrypt anything.
    key_hex = hashlib.sha256(key_bytes + secrets.token_bytes(8)).hexdigest()

    return BB84Result(
        quantum_key_hex=key_hex,
        qber=round(qber, 4),
        sifted_bits=int(len(final_key_bits)),
        session_aborted=bool(aborted),
        circuits_run=circuits_run,
        backend="qiskit-aer",
        total_exchanges=n_qubits,
        qubits_per_circuit=QUBITS_PER_CIRCUIT,
        full_circuits=full_circuits,
        remainder_qubits=remainder_qubits,
    )


def quantum_backend_info() -> dict:
    """Diagnostic info proving a real Qiskit backend is wired up —
    used by GET /api/quantum/info. The sample circuit shown is a real
    QUBITS_PER_CIRCUIT-wide batch circuit (the actual shape used to run
    BB84 exchanges), not the old single-qubit circuit."""
    if not QISKIT_AVAILABLE:
        return {"qiskit_available": False}
    import qiskit

    sample = build_bb84_batch_circuit(
        alice_bits=[1, 0, 1, 1, 0, 1][:QUBITS_PER_CIRCUIT],
        alice_bases=[BASIS_X, BASIS_Z, BASIS_Z, BASIS_X, BASIS_X, BASIS_Z][:QUBITS_PER_CIRCUIT],
        meas_bases=[BASIS_X, BASIS_X, BASIS_Z, BASIS_Z, BASIS_X, BASIS_Z][:QUBITS_PER_CIRCUIT],
    )
    return {
        "qiskit_available": True,
        "qiskit_version": qiskit.__version__,
        "simulator": getattr(_simulator, "name", str(_simulator)),
        "qubits_per_circuit": QUBITS_PER_CIRCUIT,
        "sample_circuit_diagram": str(sample.draw(output="text")),
    }
