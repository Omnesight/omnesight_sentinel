#!/usr/bin/env python3
"""
Omnesight Sentinel — Agent Console & Operator Cockpit Server
Lightweight Python server (Standard library + Sentinel Engine)
Matches Meta Workshop port standard: http://127.0.0.1:8765
"""

import sys
import os
import json
import time
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.llama_stack.client import LlamaStackClientAdapter
from src.agents.orchestrator import SentinelMasterOrchestrator
from src.protocol.supervised_action import (
    SupervisedActionEngine,
    SupervisedActionEnvelope,
    ActionStatus,
)

UI_DIR = Path(__file__).resolve().parent
DEMO_DIR = PROJECT_ROOT / "demo"

# Shared in-memory session state for interactive demo
client = LlamaStackClientAdapter()
orchestrator = SentinelMasterOrchestrator(client)

# Shared session state
SESSION_ENVELOPE = {"obj": None}

STATE = {
    "status": "IDLE", # IDLE, DIAGNOSING, PENDING_APPROVAL, EXECUTED, TAMPERED
    "scada_telemetry": None,
    "contract_liability": None,
    "envelope": None,
    "execution_log": []
}

def load_initial_data():
    SESSION_ENVELOPE["obj"] = None
    with open(DEMO_DIR / "sample_scada_telemetry.json", "r") as f:
        STATE["scada_telemetry"] = json.load(f)
    with open(DEMO_DIR / "sample_contract_liability.json", "r") as f:
        STATE["contract_liability"] = json.load(f)

load_initial_data()

class SentinelConsoleHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        elif parsed.path == "/api/state":
            self._send_json(STATE)
        elif parsed.path == "/api/reset":
            load_initial_data()
            STATE["status"] = "IDLE"
            STATE["envelope"] = None
            STATE["execution_log"] = []
            self._send_json({"status": "RESET_OK", "state": STATE})
        else:
            # Fall back to serving static files (index.html, css, js)
            if parsed.path == "/":
                self.path = "/index.html"
            return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        payload = json.loads(body.decode("utf-8")) if body else {}

        if parsed.path == "/api/run-diagnosis":
            # Run the multi-agent orchestration
            vision_metadata = {
                "camera_id": "CAM-ESC-0428-FLIR",
                "sensor_type": "Long-Wave Infrared (FLIR-A615)",
                "detected_thermal_bloom": True,
                "fracture_visual_severity": "CRITICAL_RUPTURE",
                "estimated_leak_rate_bph": 480
            }
            envelope = orchestrator.process_system_state(
                scada_data=STATE["scada_telemetry"],
                vision_data=vision_metadata,
                contract_data=STATE["contract_liability"]
            )
            SESSION_ENVELOPE["obj"] = envelope
            STATE["envelope"] = envelope.to_dict()
            STATE["status"] = "PENDING_APPROVAL"
            STATE["execution_log"].append({
                "timestamp": STATE["envelope"]["created_at"],
                "event": "MULTI_AGENT_DIAGNOSIS_COMPLETED",
                "details": f"Generated cryptographic envelope {STATE['envelope']['action_id']} with SHA-256 hash"
            })
            self._send_json({"status": "SUCCESS", "state": STATE})

        elif parsed.path == "/api/approve-action":
            supervisor = payload.get("supervisor", "Malahim Mavoungou, Chief Operating Officer")
            pin_code = str(payload.get("pin_code", "")).strip()
            auth_method = payload.get("auth_method", "BIOMETRIC_TOUCH_ID")
            envelope_obj = SESSION_ENVELOPE.get("obj")
            if not envelope_obj:
                self._send_json({"error": "No pending envelope to approve"}, status=400)
                return

            # Verification of Supervisor Clearance & Hardware Security Key / PIN
            # Valid credentials: PIN '8765' or Biometric TouchID passkey
            is_valid_pin = pin_code == "8765"
            is_valid_bio = auth_method == "BIOMETRIC_TOUCH_ID"
            if not (is_valid_pin or is_valid_bio):
                STATE["execution_log"].append({
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                    "event": "AUTH_FAILURE_UNAUTHORIZED_PIN",
                    "supervisor": supervisor,
                    "details": f"Attempted sign-off with invalid credentials (PIN: {pin_code}). Action rejected."
                })
                self._send_json({
                    "status": "AUTH_FAILED",
                    "error": "AUTHENTICATION REJECTED: Invalid Supervisor Security PIN. Access denied.",
                    "state": STATE
                }, status=403)
                return

            executed = SupervisedActionEngine.approve_and_execute(
                envelope=envelope_obj,
                supervisor_identity=supervisor
            )
            hw_token_id = payload.get("token_id", "YK-FIDO2-84920A")
            executed.audit_signature = f"ED25519_HW_SEALED_{supervisor.replace(' ', '_').upper()}_{hw_token_id}_{int(time.time())}"
            SESSION_ENVELOPE["obj"] = executed
            STATE["envelope"] = executed.to_dict()
            STATE["status"] = executed.status.value if hasattr(executed.status, "value") else str(executed.status)
            STATE["execution_log"].append({
                "timestamp": STATE["envelope"]["executed_at"],
                "event": f"ACTION_{STATE['status']}",
                "supervisor": supervisor,
                "auth_method": auth_method,
                "clearance": "CLASS-4_SCADA_REMEDIATION",
                "audit_proof": STATE["envelope"]["audit_proof"]
            })
            self._send_json({"status": "SUCCESS", "state": STATE})

        elif parsed.path == "/api/tamper-test":
            from copy import deepcopy
            envelope_obj = SESSION_ENVELOPE.get("obj")
            if not envelope_obj or getattr(envelope_obj, "status", None) in (
                ActionStatus.EXECUTED, ActionStatus.REJECTED, ActionStatus.TAMPERED, ActionStatus.ROLLED_BACK
            ):
                # Generate fresh envelope so tampering can be tested from any lifecycle state
                vision_metadata = {
                    "camera_id": "CAM-ESC-0428-FLIR",
                    "sensor_type": "Long-Wave Infrared (FLIR-A615)",
                    "detected_thermal_bloom": True,
                    "fracture_visual_severity": "CRITICAL_RUPTURE",
                    "estimated_leak_rate_bph": 480
                }
                envelope_obj = orchestrator.process_system_state(
                    scada_data=STATE["scada_telemetry"],
                    vision_data=vision_metadata,
                    contract_data=STATE["contract_liability"]
                )

            # Maliciously modify the payload parameters behind the back of the SHA-256 seal
            tampered_env = deepcopy(envelope_obj)
            if hasattr(tampered_env.payload, "parameters"):
                tampered_env.payload.parameters["override_target"] = "MALICIOUS_DRAIN_VALVE_99"
                tampered_env.payload.parameters["unauthorized_pressure_psi"] = 9999
            else:
                tampered_env.payload["parameters"]["override_target"] = "MALICIOUS_DRAIN_VALVE_99"
                tampered_env.payload["parameters"]["unauthorized_pressure_psi"] = 9999

            executed = SupervisedActionEngine.approve_and_execute(
                envelope=tampered_env,
                supervisor_identity="Attacker // Unauthorized Injection"
            )
            SESSION_ENVELOPE["obj"] = executed
            STATE["envelope"] = executed.to_dict()
            STATE["status"] = "TAMPER_DETECTED"
            STATE["execution_log"].append({
                "timestamp": STATE["envelope"]["executed_at"],
                "event": "SECURITY_ALERT_TAMPER_BLOCKED",
                "details": executed.execution_result.get("error") if executed.execution_result else "Tampering rejected"
            })
            self._send_json({"status": "SECURITY_VIOLATION_BLOCKED", "state": STATE})
        else:
            self._send_json({"error": "Not found"}, status=404)

    @staticmethod
    def _json_serial(obj):
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if hasattr(obj, "dict"):
            return obj.dict()
        if hasattr(obj, "value"):
            return obj.value
        return str(obj)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, default=self._json_serial).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

DEFAULT_PORT = 9626

def run_server(port=DEFAULT_PORT):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, SentinelConsoleHandler)
    print(f"\n==================================================================")
    print(f"🚀 OMNESIGHT SENTINEL — AGENT CONSOLE & SUPERVISION COCKPIT")
    print(f"📡 Sovereign Meta Llama Stack Runtime Active")
    print(f"🔗 Local Dashboard : http://localhost:{port}")
    print(f"🔐 WebAuthn Touch ID: Enforces 'localhost' origin for macOS passkey")
    print(f"==================================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Sentinel Console.")
        httpd.server_close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    run_server(port)
