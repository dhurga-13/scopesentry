"""Read-only API for evidence-chain verification and record metadata."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.evidence.hash_chain import EvidenceChainError
from app.evidence.service import EvidenceService, get_evidence_service
from app.schemas.evidence import (
    ChainVerificationResult,
    EvidenceRecord,
    EvidenceRecordListResponse,
)


router = APIRouter(
    prefix="/api/v1/evidence",
    tags=["Evidence"],
)


@router.get("/verify", response_model=ChainVerificationResult)
def verify_evidence_chain(
    service: EvidenceService = Depends(get_evidence_service),
) -> ChainVerificationResult:
    return service.verify()


@router.get("/records", response_model=EvidenceRecordListResponse)
def list_evidence_records(
    limit: int = Query(default=20, ge=1, le=100),
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceRecordListResponse:
    try:
        records = service.list_records(limit)
    except EvidenceChainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return EvidenceRecordListResponse(count=len(records), records=records)


@router.get("/records/{analysis_id}", response_model=EvidenceRecord)
def get_evidence_record(
    analysis_id: str,
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceRecord:
    try:
        record = service.get_record(analysis_id)
    except EvidenceChainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    return record


@router.get("/tamper-demo")
def tamper_evidence_demo(
    service: EvidenceService = Depends(get_evidence_service),
) -> dict:
    """Tamper demonstration: flips characters in the last evidence record to prove active hash verification."""
    path = service.path
    if not path.exists():
        raise HTTPException(status_code=400, detail="Evidence ledger is empty; run an analysis or scenario first.")
    
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        raise HTTPException(status_code=400, detail="Evidence ledger has no records.")
    
    # Save clean backup if not already saved
    backup_path = path.with_suffix(".jsonl.bak")
    if not backup_path.exists():
        backup_path.write_text(text, encoding="utf-8")
    
    # Mutate the last line's decision_summary
    last_line = lines[-1]
    import json
    data = json.loads(last_line)
    data["decision_summary"] = data.get("decision_summary", "") + " [TAMPERED_BY_ATTACKER]"
    lines[-1] = json.dumps(data)
    
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "status": "tampered",
        "message": f"Record #{data.get('sequence_number')} altered. Hash chain verification will now fail.",
        "tampered_sequence": data.get("sequence_number"),
    }


@router.get("/restore-demo")
def restore_evidence_demo(
    service: EvidenceService = Depends(get_evidence_service),
) -> dict:
    """Restore demonstration: restores pristine evidence ledger from backup."""
    path = service.path
    backup_path = path.with_suffix(".jsonl.bak")
    if backup_path.exists():
        path.write_text(backup_path.read_text(encoding="utf-8"), encoding="utf-8")
        backup_path.unlink()
        return {"status": "restored", "message": "Pristine cryptographic evidence ledger restored."}
    return {"status": "intact", "message": "Ledger is already in pristine state."}
