from __future__ import annotations

from fastapi import APIRouter, Depends

from policy.ml_risk import MLRiskModel
from policy.risk import RiskEngine, RiskFactors

from ..dependencies import get_current_user, get_risk_engine
from ..schemas import MLRiskFactorResponse, RiskAssessRequest, RiskAssessResponse

router = APIRouter(prefix="/api/risk", tags=["risk"])

# Stateless and cheap to construct; a single shared instance is fine
# for a hackathon prototype (mirrors get_risk_engine's own module-level
# simplicity — see api/dependencies.py).
_ml_model = MLRiskModel()


@router.post("/assess", response_model=RiskAssessResponse)
def assess_risk(
    payload: RiskAssessRequest,
    engine: RiskEngine = Depends(get_risk_engine),
    _user=Depends(get_current_user),
) -> RiskAssessResponse:
    factors = RiskFactors(**payload.model_dump())
    result = engine.assess(factors)
    ml_result = _ml_model.assess(factors)
    return RiskAssessResponse(
        score=result.score,
        level=result.level.value,
        action=result.action.value,
        ai_risk_probability=ml_result.probability,
        ai_risk_level=ml_result.level.value,
        ai_top_factors=[
            MLRiskFactorResponse(
                feature=f.feature, value=f.value, weight=f.weight, contribution=round(f.contribution, 4)
            )
            for f in ml_result.top_factors
        ],
    )
