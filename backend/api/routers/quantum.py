from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from quantum.service import QuantumKeyExchangeService

from ..dependencies import get_current_user, get_quantum_service
from ..schemas import QuantumGenerateKeyRequest, QuantumGenerateKeyResponse

router = APIRouter(prefix="/api/quantum", tags=["quantum"])


@router.post("/generate-key", response_model=QuantumGenerateKeyResponse)
def generate_key(
    payload: QuantumGenerateKeyRequest,
    service: QuantumKeyExchangeService = Depends(get_quantum_service),
    _user=Depends(get_current_user),
) -> QuantumGenerateKeyResponse:
    try:
        result = service.generate_shared_key(
            eavesdrop_prob=payload.eavesdrop_prob, n_qubits=payload.n_qubits
        )
    except RuntimeError as exc:  # qiskit not installed
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    return QuantumGenerateKeyResponse(
        quantum_key_hex=result.quantum_key_hex,
        qber=result.qber,
        sifted_bits=result.sifted_bits,
        session_aborted=result.session_aborted,
        total_exchanges=result.total_exchanges,
        qubits_per_circuit=result.qubits_per_circuit,
        full_circuits=result.full_circuits,
        remainder_qubits=result.remainder_qubits,
    )


@router.get("/info")
def backend_info(service: QuantumKeyExchangeService = Depends(get_quantum_service)) -> dict:
    """No auth required — easy to curl to prove a real Qiskit backend is wired up."""
    return service.backend_info()
