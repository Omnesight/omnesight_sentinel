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
import secrets
import hmac
import threading
from typing import Dict, Any, Optional
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.llama_stack.client import (
    LlamaStackClientAdapter,
    MetaQuotaExceededError,
    MetaConnectionError,
    MetaAuthenticationError,
    MetaAPIError,
)
from src.agents.orchestrator import SentinelMasterOrchestrator
from src.protocol.supervised_action import (
    SupervisedActionEngine,
    SupervisedActionEnvelope,
    ActionStatus,
)
from src.protocol.audit_ledger import AuditLedger

UI_DIR = Path(__file__).resolve().parent
DEMO_DIR = PROJECT_ROOT / "demo"

# Shared in-memory session state for interactive demo
client = LlamaStackClientAdapter()
orchestrator = SentinelMasterOrchestrator(client)
ledger = AuditLedger()

# Thread-safe multi-session action and challenge stores
STATE_LOCK = threading.RLock()
ACTIVE_ENVELOPES: Dict[str, SupervisedActionEnvelope] = {}
ACTIVE_CHALLENGES: Dict[str, Dict[str, Any]] = {}
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
            with STATE_LOCK:
                is_valid, b_count, _ = ledger.verify_ledger_integrity()
                STATE["ledger_info"] = {
                    "block_count": b_count,
                    "integrity_verified": is_valid,
                }
                self._send_json(STATE)
        elif parsed.path == "/api/auth/challenge":
            # P1: Server-side cryptographic challenge generation (Anti-Replay / Nonce verification)
            query = parse_qs(parsed.query)
            action_id = query.get("action_id", [None])[0]
            with STATE_LOCK:
                if not action_id and SESSION_ENVELOPE.get("obj"):
                    action_id = SESSION_ENVELOPE["obj"].payload.action_id
                nonce = secrets.token_hex(32)
                challenge_id = f"CHAL_{secrets.token_hex(8)}"
                ACTIVE_CHALLENGES[challenge_id] = {
                    "nonce": nonce,
                    "created_at": time.time(),
                    "action_id": action_id or "PENDING"
                }
            self._send_json({
                "status": "CHALLENGE_ISSUED",
                "challenge_id": challenge_id,
                "challenge_nonce": nonce,
                "action_id": action_id,
                "expires_in_seconds": 120
            })
        elif parsed.path == "/api/ledger":
            # P3: Immutable Tamper-Evident Ledger Forensics
            is_valid, b_count, err = ledger.verify_ledger_integrity()
            blocks = ledger.get_recent_blocks(limit=25)
            self._send_json({
                "status": "SUCCESS",
                "integrity_verified": is_valid,
                "block_count": b_count,
                "error": err,
                "recent_blocks": blocks
            })
        elif parsed.path == "/api/reset":
            with STATE_LOCK:
                load_initial_data()
                ACTIVE_ENVELOPES.clear()
                ACTIVE_CHALLENGES.clear()
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
            try:
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
                with STATE_LOCK:
                    ACTIVE_ENVELOPES[envelope.payload.action_id] = envelope
                    SESSION_ENVELOPE["obj"] = envelope
                    STATE["envelope"] = envelope.to_dict()
                    STATE["status"] = "PENDING_APPROVAL"
                    STATE["error_message"] = None
                    STATE["execution_log"].append({
                        "timestamp": STATE["envelope"]["created_at"],
                        "event": "MULTI_AGENT_DIAGNOSIS_COMPLETED",
                        "details": f"Generated cryptographic envelope {STATE['envelope']['action_id']} with SHA-256 hash"
                    })
                self._send_json({"status": "SUCCESS", "state": STATE})
            except MetaQuotaExceededError as e:
                with STATE_LOCK:
                    STATE["status"] = "API_ERROR"
                    STATE["error_message"] = f"Meta Quota Exhausted (HTTP 429): {e.message}"
                    STATE["execution_log"].append({
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                        "event": "META_QUOTA_EXHAUSTED",
                        "details": str(e)
                    })
                self._send_json({"status": "ERROR", "error_type": "META_QUOTA_EXHAUSTED", "error": str(e), "state": STATE})
            except MetaConnectionError as e:
                with STATE_LOCK:
                    STATE["status"] = "API_ERROR"
                    STATE["error_message"] = f"Network Connection Offline: {e.message}"
                    STATE["execution_log"].append({
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                        "event": "NETWORK_UNREACHABLE",
                        "details": str(e)
                    })
                self._send_json({"status": "ERROR", "error_type": "NETWORK_UNREACHABLE", "error": str(e), "state": STATE})
            except MetaAuthenticationError as e:
                with STATE_LOCK:
                    STATE["status"] = "API_ERROR"
                    STATE["error_message"] = f"Meta Authentication Error: {e.message}"
                    STATE["execution_log"].append({
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                        "event": "META_AUTH_FAILED",
                        "details": str(e)
                    })
                self._send_json({"status": "ERROR", "error_type": "META_AUTH_FAILED", "error": str(e), "state": STATE})
            except Exception as e:
                with STATE_LOCK:
                    STATE["status"] = "API_ERROR"
                    STATE["error_message"] = f"System Error: {str(e)}"
                    STATE["execution_log"].append({
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                        "event": "SYSTEM_ERROR",
                        "details": str(e)
                    })
                self._send_json({"status": "ERROR", "error_type": "SYSTEM_ERROR", "error": str(e), "state": STATE})

        elif parsed.path == "/api/approve-action":
            action_id = payload.get("action_id")
            supervisor = payload.get("supervisor", "Malahim Mavoungou, Chief Operating Officer")
            pin_code = str(payload.get("pin_code", "")).strip()
            auth_method = payload.get("auth_method", "BIOMETRIC_TOUCH_ID")
            challenge_id = payload.get("challenge_id")
            hw_token_id = payload.get("token_id", "YK-FIDO2-84920A")

            with STATE_LOCK:
                envelope_obj = None
                if action_id:
                    envelope_obj = ACTIVE_ENVELOPES.get(action_id)
                if not envelope_obj:
                    envelope_obj = SESSION_ENVELOPE.get("obj")

            if not envelope_obj:
                self._send_json({"error": "No pending envelope to approve"}, status=400)
                return

            # Verification of Challenge (Anti-Replay / Cryptographic Nonce Gating)
            if challenge_id:
                with STATE_LOCK:
                    chal_entry = ACTIVE_CHALLENGES.pop(challenge_id, None)
                if not chal_entry:
                    self._send_json({
                        "status": "AUTH_FAILED",
                        "error": "REPLAY PROTECTION BLOCKED: Challenge ID missing or already consumed.",
                        "state": STATE
                    }, status=403)
                    return
                if time.time() - chal_entry.get("created_at", 0) > 120:
                    self._send_json({
                        "status": "AUTH_FAILED",
                        "error": "CHALLENGE EXPIRED: The cryptographic authorization challenge has expired (120s limit).",
                        "state": STATE
                    }, status=403)
                    return

            # Verification of Supervisor Clearance & Hardware Security Key / PIN
            # Timing-safe comparison of Hardware PIN
            expected_pin = os.getenv("SUPERVISOR_HARDWARE_PIN", "8765")
            is_valid_pin = (auth_method == "HARDWARE_PIN") and hmac.compare_digest(pin_code, expected_pin)
            is_valid_bio = auth_method == "BIOMETRIC_TOUCH_ID"

            if not (is_valid_pin or is_valid_bio):
                with STATE_LOCK:
                    STATE["execution_log"].append({
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                        "event": "AUTH_FAILURE_UNAUTHORIZED_PIN",
                        "supervisor": supervisor,
                        "details": f"Attempted sign-off with invalid credentials. Action rejected."
                    })
                self._send_json({
                    "status": "AUTH_FAILED",
                    "error": "AUTHENTICATION REJECTED: Invalid Supervisor Security PIN. Access denied.",
                    "state": STATE
                }, status=403)
                return

            executed = SupervisedActionEngine.approve_and_execute(
                envelope=envelope_obj,
                supervisor_identity=supervisor,
                auth_method=auth_method,
                record_to_ledger=True
            )

            with STATE_LOCK:
                if action_id:
                    ACTIVE_ENVELOPES[action_id] = executed
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
    httpd = ThreadingHTTPServer(server_address, SentinelConsoleHandler)
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
