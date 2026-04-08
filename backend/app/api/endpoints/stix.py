import os
import json
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.services.stix_parser import parse_stix
from ml_pipeline.pipeline import run_pipeline

router = APIRouter()

@router.post("/upload")
async def upload_stix(file: UploadFile = File(...)):
    """
    Endpoint to trigger STIX ingestion, validation, and full pipeline.
    """
    try:
        content = await file.read()
        
        # 1. Parse & Validate
        parsed_data = parse_stix(content, file.filename)
        
        if not parsed_data.get('valid'):
            return {"status": "error", "message": "Invalid STIX data", "errors": parsed_data.get('errors')}
        
        # 2. Run Pipeline (DB insertion, ML inference, Trust Scoring)
        report = run_pipeline(parsed_data)
        
        return {"status": "success", "report": report}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process STIX file: {str(e)}")
