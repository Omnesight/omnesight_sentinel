"""
Omnesight Sentinel — REST API Microservice
Exposes Meta Llama Stack Agent Pipeline & Supervised Action Protocol via FastAPI
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

# Ensure project root is in sys.path when invoked directly via `python src/server.py`
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from src.llama_stack.client import LlamaStackClientAdapter
from src.agents.orchestrator import SentinelMasterOrchestrator
from src.protocol.supervised_action import SupervisedActionEngine, SupervisedActionEnvelope

app = FastAPI(
    title="Omnesight Sentinel API",
    version="1.0.0",
    description="Sovereign Operational Intelligence API powered by Meta Llama Stack & Supervised Action Protocol."
)

client = LlamaStackClientAdapter()
orchestrator = SentinelMasterOrchestrator(client)

class TelemetryInspectionRequest(BaseModel):
    scada_data: Dict[str, Any]
    vision_data: Dict[str, Any]
    contract_data: Dict[str, Any]

class ActionApprovalRequest(BaseModel):
    envelope: SupervisedActionEnvelope
    supervisor_identity: str = Field(..., description="Corporate identity of the approving executive")

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "HEALTHY",
        "service": "Omnesight Sentinel",
        "llama_stack_connected": client.has_live_endpoint,
        "runtime_version": "2026.1-llama-stack"
    }

@app.post("/api/v1/sentinel/process-incident", response_model=SupervisedActionEnvelope, tags=["Agents"])
def process_incident(request: TelemetryInspectionRequest):
    """
    Ingests multimodal SCADA + Vision telemetry, runs Llama 3.2 multi-agent diagnosis,
    and returns a cryptographically hashed Supervised Action Protocol envelope.
    """
    try:
        envelope = orchestrator.process_system_state(
            scada_data=request.scada_data,
            vision_data=request.vision_data,
            contract_data=request.contract_data
        )
        return envelope
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/sentinel/execute-action", response_model=SupervisedActionEnvelope, tags=["Supervised Action Protocol"])
def execute_supervised_action(request: ActionApprovalRequest):
    """
    Validates cryptographic integrity (SHA-256) and executes the approved action
    with an immutable audit ledger entry.
    """
    try:
        executed_envelope = SupervisedActionEngine.approve_and_execute(
            envelope=request.envelope,
            supervisor_identity=request.supervisor_identity
        )
        if executed_envelope.status == "REJECTED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=executed_envelope.execution_result.get("error", "Action validation failed")
            )
        return executed_envelope
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.server:app", host="0.0.0.0", port=8000, reload=True, app_dir=str(PROJECT_ROOT))
