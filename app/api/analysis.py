from fastapi import APIRouter, Depends, HTTPException
from app.evidence.service import EvidenceService, get_evidence_service
from app.planner.analysis_service import (
    UnsupportedAnalysisProviderError,
    analyze_scope_grant,
)
from app.schemas.analysis import (
    ScopeAnalysisRequest,
    ScopeAnalysisResponse,
)

router = APIRouter(
    prefix="/api/v1",
    tags=["Scope Analysis"],
)


@router.post("/analyze", response_model=ScopeAnalysisResponse)
def analyze_scopes(
    request: ScopeAnalysisRequest,
    evidence_service: EvidenceService = Depends(get_evidence_service),
) -> ScopeAnalysisResponse:
    try:
        result = analyze_scope_grant(
            provider=request.provider,
            granted_scopes=request.granted_scopes,
            intended_actions=request.intended_actions,
        )
    except UnsupportedAnalysisProviderError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    evidence_reference = evidence_service.create_record(
        analysis_type="single_grant",
        request={**request.model_dump(mode="json"), "provider": result["provider"]},
        result=result,
        decision_summary=result["recommendation"],
    )
    return ScopeAnalysisResponse(
        **result,
        evidence_reference=evidence_reference,
    )


@router.get("/analyze", response_model=ScopeAnalysisResponse)
def analyze_scopes_get(
    provider: str = "google",
    scopes: str = "drive.readonly",
    intents: str = "read files",
    evidence_service: EvidenceService = Depends(get_evidence_service),
) -> ScopeAnalysisResponse:
    granted_scopes = [s.strip() for s in scopes.split(",") if s.strip()]
    intended_actions = [i.strip() for i in intents.split(",") if i.strip()]
    req = ScopeAnalysisRequest(
        provider=provider,
        granted_scopes=granted_scopes,
        intended_actions=intended_actions,
    )
    return analyze_scopes(req, evidence_service)
