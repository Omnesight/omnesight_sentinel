"""
Comprehensive Unit & Adversarial Red-Team Test Suite for Omnesight Sentinel
Verifies:
- Supervised Action Protocol (SAP) Cryptographic Integrity (SHA-256 + HMAC)
- Canonical JSON Serialization Determinism
- Offensive Security / Hack Simulations (MITM Parameter Tampering, Target Hijacking,
  Severity Downgrade, Rollback Poisoning, Forged Digest, Replay Attacks, Zero-Trust Identity Bypass)
- Deterministic Rollback Engine & Irreversible Action Guards
- Meta Llama Stack Multimodal Orchestrator Pipeline (Llama 3.2 Vision & Text)
- FastAPI REST Microservice Endpoints & Security Rejections
"""

import sys
import os
import json
import tempfile
import concurrent.futures
from copy import deepcopy
from pathlib import Path

# Ensure project root is in sys.path when invoked directly via `python tests/test_sentinel.py`
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from unittest.mock import patch, MagicMock
from src.protocol.supervised_action import (
    SupervisedActionEngine,
    ActionPayload,
    ActionSeverity,
    ActionStatus,
)
from src.llama_stack.client import (
    LlamaStackClientAdapter,
    MetaQuotaExceededError,
    MetaConnectionError,
    MetaAuthenticationError,
)
from src.agents.orchestrator import SentinelMasterOrchestrator


# ============================================================================
# 1. CORE CRYPTOGRAPHIC INTEGRITY & DETERMINISM TESTS
# ============================================================================

def test_supervised_action_cryptographic_integrity():
    """Verifies standard end-to-end proposal, SHA-256 sealing, and supervisor execution."""
    envelope = SupervisedActionEngine.propose_action(
        action_id="act_test_001",
        target_system="scada.valves.valve_01",
        command="THROTTLE_50",
        parameters={"rate": 500, "unit": "m3h"},
        severity=ActionSeverity.HIGH,
        estimated_impact="Test impact calculation",
        rollback_command="RESTORE_100",
        rollback_parameters={"rate": 1000, "unit": "m3h"},
    )

    assert envelope.status == ActionStatus.AWAITING_SUPERVISOR_APPROVAL
    assert len(envelope.payload_sha256) == 64  # Valid 256-bit hex digest

    executed = SupervisedActionEngine.approve_and_execute(
        envelope=envelope,
        supervisor_identity="OPERATOR_TEST_CHIEF",
    )

    assert executed.status == ActionStatus.EXECUTED
    assert executed.supervisor_identity == "OPERATOR_TEST_CHIEF"
    assert "HMAC_SIGNED_OPERATOR_TEST_CHIEF" in executed.audit_signature
    assert SupervisedActionEngine.verify_audit_signature(executed) is True
    assert executed.execution_result["execution_status"] == "SUCCESS"
    assert executed.execution_result["verified"] is True


def test_canonical_json_hash_determinism():
    """Ensures parameter key ordering differences produce identical canonical SHA-256 hashes."""
    ts = 1793000000.0
    p1 = ActionPayload(
        action_id="act_det_01",
        timestamp=ts,
        target_system="scada.grid.node_a",
        command="MODULATE",
        parameters={"alpha": 1, "zeta": 99, "beta": {"x": 10, "a": 20}},
        severity=ActionSeverity.MEDIUM,
        estimated_impact="Deterministic test",
    )
    p2 = ActionPayload(
        action_id="act_det_01",
        timestamp=ts,
        target_system="scada.grid.node_a",
        command="MODULATE",
        parameters={"zeta": 99, "beta": {"a": 20, "x": 10}, "alpha": 1},
        severity=ActionSeverity.MEDIUM,
        estimated_impact="Deterministic test",
    )

    hash_1 = SupervisedActionEngine.compute_payload_hash(p1)
    hash_2 = SupervisedActionEngine.compute_payload_hash(p2)
    assert hash_1 == hash_2, "Canonical JSON serialization must be invariant to key order"


# ============================================================================
# 2. OFFENSIVE RED-TEAM / HACK SIMULATION TESTS
# ============================================================================

def test_hack_financial_parameter_injection():
    """[HACK] MITM attacker inflates SBLC treasury transfer from $100k to $9.99M after LLM formulation."""
    envelope = SupervisedActionEngine.propose_action(
        action_id="act_tamper_002",
        target_system="banking.treasury.sblc",
        command="RELEASE_PAYMENT",
        parameters={"amount_usd": 100000, "beneficiary": "NNPC_ESCROW"},
        severity=ActionSeverity.CRITICAL,
        estimated_impact="Legitimate payment",
    )

    # Malicious tampering: modify parameter after agent formulation
    envelope.payload.parameters["amount_usd"] = 9999999

    tampered_result = SupervisedActionEngine.approve_and_execute(
        envelope=envelope,
        supervisor_identity="ATTACKER_MITM",
    )

    assert tampered_result.status == ActionStatus.REJECTED
    assert tampered_result.execution_result["verified"] is False
    assert tampered_result.execution_result["security_code"] == "ERR_SHA256_TAMPER_DETECTED"


def test_hack_scada_target_hijacking():
    """[HACK] Attacker redirects a safe pipeline throttle to an unauthorized emergency drain valve."""
    envelope = SupervisedActionEngine.propose_action(
        action_id="act_hijack_003",
        target_system="scada.pipeline.escravos_lagos.valve_12",
        command="THROTTLE_INFLOW_TO_65_PERCENT",
        parameters={"valve_angle_deg": 42.5},
        severity=ActionSeverity.CRITICAL,
        estimated_impact="Prevent flange rupture",
    )

    # Hijack target subsystem
    envelope.payload.target_system = "scada.pipeline.emergency_blowdown_vent_99"

    result = SupervisedActionEngine.approve_and_execute(
        envelope=envelope,
        supervisor_identity="OPERATOR_CHIEF",
    )

    assert result.status == ActionStatus.REJECTED
    assert result.execution_result["verified"] is False
    assert result.execution_result["security_code"] == "ERR_SHA256_TAMPER_DETECTED"


def test_hack_command_escalation_and_severity_downgrade():
    """[HACK] Attacker swaps command to FULL_SHUTDOWN while downgrading severity to LOW to evade alerts."""
    envelope = SupervisedActionEngine.propose_action(
        action_id="act_downgrade_004",
        target_system="scada.pipeline.escravos_lagos.valve_12",
        command="THROTTLE_INFLOW_TO_65_PERCENT",
        parameters={"rate_limit_m3h": 18500},
        severity=ActionSeverity.CRITICAL,
        estimated_impact="Controlled pressure stabilization",
    )

    envelope.payload.command = "FORCE_TOTAL_SHUTDOWN"
    envelope.payload.severity = ActionSeverity.LOW

    result = SupervisedActionEngine.approve_and_execute(
        envelope=envelope,
        supervisor_identity="OPERATOR_CHIEF",
    )

    assert result.status == ActionStatus.REJECTED
    assert result.execution_result["security_code"] == "ERR_SHA256_TAMPER_DETECTED"


def test_hack_rollback_poisoning_attack():
    """[HACK] Stealth attack: leaves primary command intact but poisons the rollback recovery command."""
    envelope = SupervisedActionEngine.propose_action(
        action_id="act_rollback_poison_005",
        target_system="scada.valves.bonny_gate_12",
        command="THROTTLE_65",
        parameters={"pressure_bar": 54.0},
        severity=ActionSeverity.HIGH,
        estimated_impact="Stabilize flange pressure",
        rollback_command="RESTORE_NOMINAL_100",
        rollback_parameters={"pressure_bar": 59.0},
    )

    # Poison rollback parameters behind the scenes
    envelope.payload.rollback_command = "DISABLE_OVERPRESSURE_RELIEF"
    envelope.payload.rollback_parameters["pressure_bar"] = 250.0

    result = SupervisedActionEngine.approve_and_execute(
        envelope=envelope,
        supervisor_identity="OPERATOR_CHIEF",
    )

    assert result.status == ActionStatus.REJECTED
    assert result.execution_result["security_code"] == "ERR_SHA256_TAMPER_DETECTED"


def test_hack_forged_sha256_signature_swap():
    """[HACK] Attacker injects a forged 64-char SHA-256 signature into the envelope."""
    envelope = SupervisedActionEngine.propose_action(
        action_id="act_forged_sig_006",
        target_system="scada.turbine.unit_04",
        command="SET_RPM",
        parameters={"rpm": 3600},
        severity=ActionSeverity.MEDIUM,
        estimated_impact="Nominal sync",
    )

    envelope.payload_sha256 = "f" * 64  # Forged digest

    result = SupervisedActionEngine.approve_and_execute(
        envelope=envelope,
        supervisor_identity="OPERATOR_CHIEF",
    )

    assert result.status == ActionStatus.REJECTED
    assert result.execution_result["security_code"] == "ERR_SHA256_TAMPER_DETECTED"


def test_hack_replay_attack_double_execution():
    """[HACK] Attacker captures an already EXECUTED envelope and replays it to trigger duplicate execution."""
    envelope = SupervisedActionEngine.propose_action(
        action_id="act_replay_007",
        target_system="banking.sblc.settlement",
        command="DISBURSE_COLLATERAL_TRANCHE",
        parameters={"tranche_usd": 340000},
        severity=ActionSeverity.CRITICAL,
        estimated_impact="Single authorized settlement tranche",
    )

    # First legitimate execution
    first_exec = SupervisedActionEngine.approve_and_execute(
        envelope=envelope,
        supervisor_identity="MALAHIM_MAVOUNGOU_COO",
    )
    assert first_exec.status == ActionStatus.EXECUTED

    # Malicious Replay Attack: re-submitting the captured envelope
    replay_attempt = SupervisedActionEngine.approve_and_execute(
        envelope=first_exec,
        supervisor_identity="MALAHIM_MAVOUNGOU_COO",
    )

    assert replay_attempt.status == ActionStatus.REJECTED
    assert replay_attempt.execution_result["verified"] is False
    assert replay_attempt.execution_result["security_code"] == "ERR_REPLAY_ATTACK_DETECTED"


def test_hack_zero_trust_anonymous_supervisor_bypass():
    """[HACK] Attacker attempts to bypass audit attribution using empty or anonymous identities."""
    for invalid_id in ["", "   ", "ANONYMOUS", "null", "unknown"]:
        envelope = SupervisedActionEngine.propose_action(
            action_id="act_unauth_008",
            target_system="scada.valves.valve_01",
            command="OPEN_VALVE",
            parameters={"pct": 100},
            severity=ActionSeverity.HIGH,
            estimated_impact="Test zero-trust identity check",
        )
        res = SupervisedActionEngine.approve_and_execute(
            envelope=envelope,
            supervisor_identity=invalid_id,
        )
        assert res.status == ActionStatus.REJECTED
        assert res.execution_result["security_code"] == "ERR_ZERO_TRUST_IDENTITY_MISSING"


# ============================================================================
# 3. DETERMINISTIC ROLLBACK & SAFETY GUARD TESTS
# ============================================================================

def test_deterministic_rollback_and_irreversible_guard():
    """Verifies safe rollback of an executed action and strict rejection of irreversible rollbacks."""
    reversible_env = SupervisedActionEngine.propose_action(
        action_id="act_rev_009",
        target_system="scada.pipeline.valve_12",
        command="THROTTLE_65",
        parameters={"angle": 42.5},
        severity=ActionSeverity.CRITICAL,
        estimated_impact="Reversible throttle",
        rollback_command="RESTORE_100",
        rollback_parameters={"angle": 90.0},
    )

    # Cannot rollback before execution
    try:
        SupervisedActionEngine.rollback_action(reversible_env, "COO_SUPERVISOR")
        assert False, "Should not allow rollback before action is EXECUTED"
    except ValueError:
        pass

    # Execute then rollback
    SupervisedActionEngine.approve_and_execute(reversible_env, "COO_SUPERVISOR")
    rolled_back = SupervisedActionEngine.rollback_action(reversible_env, "COO_SUPERVISOR")
    assert rolled_back.status == ActionStatus.ROLLED_BACK
    assert rolled_back.execution_result["executed_command"] == "RESTORE_100"

    # Non-reversible action must block rollback
    irreversible_env = SupervisedActionEngine.propose_action(
        action_id="act_irrev_010",
        target_system="legal.notice.force_majeure",
        command="DISPATCH_REGULATORY_FILING",
        parameters={"filing_id": "FM-2026-99"},
        severity=ActionSeverity.HIGH,
        estimated_impact="Irreversible legal filing",
        rollback_command=None,
    )
    SupervisedActionEngine.approve_and_execute(irreversible_env, "COO_SUPERVISOR")
    try:
        SupervisedActionEngine.rollback_action(irreversible_env, "COO_SUPERVISOR")
        assert False, "Should raise ValueError when attempting to rollback a non-reversible action"
    except ValueError:
        pass


# ============================================================================
# 4. MULTI-AGENT LLAMA STACK & ENTERPRISE ERROR HANDLING TESTS
# ============================================================================

def test_meta_api_quota_exhausted_error_handling():
    """Verifies that HTTP 429 from Meta Model API raises explicit MetaQuotaExceededError."""
    client = LlamaStackClientAdapter(api_key="TEST_KEY", allow_fallback=False)
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "Quota limit reached: Token allocation exhausted on project"
        mock_post.return_value = mock_resp

        try:
            client.analyze_multimodal_telemetry({}, {})
            assert False, "Expected MetaQuotaExceededError on HTTP 429"
        except MetaQuotaExceededError as exc:
            assert exc.status_code == 429
            assert exc.error_code == "META_QUOTA_EXHAUSTED"
            assert "Quota" in exc.message


def test_meta_api_network_connection_error_handling():
    """Verifies that network outage raises explicit MetaConnectionError with Zero-Trust halt."""
    import requests
    client = LlamaStackClientAdapter(api_key="TEST_KEY", allow_fallback=False)
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused by gateway")):
        try:
            client.analyze_multimodal_telemetry({}, {})
            assert False, "Expected MetaConnectionError when offline"
        except MetaConnectionError as exc:
            assert exc.error_code == "NETWORK_UNREACHABLE"
            assert "Connexion Internet" in exc.message or "Network" in exc.message


@patch.object(LlamaStackClientAdapter, "_call_meta_model_api")
def test_full_orchestrator_pipeline(mock_call):
    """Verifies Multimodal Llama 3.2 Vision + Financial Risk Agent orchestration."""
    mock_call.side_effect = [
        {
            "model_used": "muse-spark-1.3",
            "anomaly_detected": True,
            "anomaly_type": "RAPID_PRESSURE_DROP_WITH_OPTICAL_FLANGE_MICRO_LEAK",
            "confidence_score": 0.984,
            "severity": "CRITICAL",
            "root_cause_diagnosis": (
                "Flange seal degradation detected at Escravos-Lagos Pipeline (ELPS) Sector 12B. "
                "Correlating 4.2 bar drop with thermal optical signatures at Bonny Terminal intake valve #12."
            ),
            "recommended_action": {
                "target_system": "scada.pipeline.escravos_lagos.valve_12",
                "command": "THROTTLE_INFLOW_TO_65_PERCENT",
                "parameters": {
                    "valve_id": "ELPS-VALVE-12",
                    "reroute_line": "WEST-GRID-BYPASS-02",
                    "valve_angle_deg": 42.5,
                    "rate_limit_m3h": 18500
                },
                "rollback_command": "RESTORE_INFLOW_TO_100_PERCENT",
                "rollback_parameters": {
                    "valve_id": "ELPS-VALVE-12",
                    "reroute_line": "WEST-GRID-BYPASS-02",
                    "valve_angle_deg": 90.0,
                    "rate_limit_m3h": 28000
                }
            }
        },
        {
            "model_used": "muse-spark-1.3",
            "counterparty": "NNPC",
            "contract_type": "Take-or-Pay",
            "hourly_penalty_risk_usd": 340000.0,
            "mitigation_window_minutes": 45,
            "financial_action_required": (
                "Issue automated electronic Notice of Force Majeure / Scheduled Pressure Modulation "
                "to eliminate liquidated damages, and trigger Standby Letter of Credit (SBLC) covenant verification."
            ),
            "estimated_loss_prevented_usd": 1360000.0
        }
    ]

    client = LlamaStackClientAdapter(allow_fallback=True)
    orchestrator = SentinelMasterOrchestrator(client)

    scada_data = {
        "corridor": "Escravos-Lagos Pipeline",
        "current_pressure_bar": 54.0,
        "nominal_pressure_bar": 59.0,
        "timestamp": 1792948800,
    }
    vision_data = {
        "camera_id": "BONNY-CAM-01",
        "optical_anomaly_detected": "THERMAL_LEAK",
    }
    contract_data = {
        "counterparty": "NNPC",
        "contract_type": "Take-or-Pay",
    }

    envelope = orchestrator.process_system_state(scada_data, vision_data, contract_data)
    assert envelope.payload.severity == ActionSeverity.CRITICAL
    assert "Take-or-Pay" in envelope.payload.estimated_impact
    assert "$1,360,000" in envelope.payload.estimated_impact
    assert envelope.payload.reversibility is True

    # Verify UI serialization helper
    ui_dict = envelope.to_dict()
    assert ui_dict["payload_hash"] == envelope.payload_sha256
    assert ui_dict["proposed_action"]["type"] == "THROTTLE_INFLOW_TO_65_PERCENT"


@patch.object(LlamaStackClientAdapter, "_call_meta_model_api")
def test_fastapi_rest_endpoints_and_tamper_rejection(mock_meta):
    """Verifies FastAPI REST handlers directly, including HTTP 400 rejection on tampered envelopes."""
    mock_meta.side_effect = [
        {
            "model_used": "muse-spark-1.3",
            "anomaly_detected": True,
            "anomaly_type": "RAPID_PRESSURE_DROP_WITH_OPTICAL_FLANGE_MICRO_LEAK",
            "confidence_score": 0.984,
            "severity": "CRITICAL",
            "root_cause_diagnosis": "Flange degradation detected.",
            "recommended_action": {
                "target_system": "scada.pipeline.escravos_lagos.valve_12",
                "command": "THROTTLE_INFLOW_TO_65_PERCENT",
                "parameters": {"valve_id": "ELPS-VALVE-12", "rate_limit_m3h": 18500},
                "rollback_command": "RESTORE_INFLOW_TO_100_PERCENT",
                "rollback_parameters": {"valve_id": "ELPS-VALVE-12", "rate_limit_m3h": 28000}
            }
        },
        {
            "model_used": "muse-spark-1.3",
            "counterparty": "NNPC",
            "contract_type": "Take-or-Pay",
            "hourly_penalty_risk_usd": 340000.0,
            "mitigation_window_minutes": 45,
            "financial_action_required": "Issue electronic Force Majeure notice.",
            "estimated_loss_prevented_usd": 1360000.0
        }
    ]
    from fastapi import HTTPException
    import src.server as srv
    srv.client.allow_fallback = True

    health = srv.health_check()
    assert health["status"] == "HEALTHY"
    assert health["service"] == "Omnesight Sentinel"

    req = srv.TelemetryInspectionRequest(
        scada_data={"corridor": "ELPS", "current_pressure_bar": 54.8, "nominal_pressure_bar": 59.0, "timestamp": 1793001111},
        vision_data={"camera_id": "CAM-04", "optical_anomaly_detected": "FLANGE_SPRAY"},
        contract_data={"counterparty": "NNPC", "contract_type": "Take-or-Pay"},
    )
    envelope = srv.process_incident(req)
    assert envelope.status == ActionStatus.AWAITING_SUPERVISOR_APPROVAL

    # 1. Tamper with envelope and verify FastAPI raises HTTP 400
    tampered_env = deepcopy(envelope)
    tampered_env.payload.parameters["rate_limit_m3h"] = 999999
    try:
        srv.execute_supervised_action(
            srv.ActionApprovalRequest(envelope=tampered_env, supervisor_identity="COO_SUPERVISOR")
        )
        assert False, "Expected HTTPException 400 on tampered payload"
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "Cryptographic mismatch" in exc.detail

    # 2. Execute untampered envelope via FastAPI handler
    approved_env = srv.execute_supervised_action(
        srv.ActionApprovalRequest(envelope=envelope, supervisor_identity="COO_SUPERVISOR")
    )
    assert approved_env.status == ActionStatus.EXECUTED


# ============================================================================
# 5. CRYPTOGRAPHIC ENCLAVE SIGNATURE, LEDGER CHAINING & CONCURRENCY TESTS
# ============================================================================

def test_real_hmac_cryptographic_verification_and_tamper_rejection():
    """
    [P0 Security Test] Proves HMAC-SHA256 cannot be forged without the enclave secret key,
    and any modification to payload, supervisor identity, or timestamp is immediately rejected.
    """
    secret = "enclave_test_secret_key_9988"
    envelope = SupervisedActionEngine.propose_action(
        action_id="act_crypto_test_01",
        target_system="scada.valves.valve_12",
        command="THROTTLE_65",
        parameters={"rate": 65, "unit": "pct"},
        severity=ActionSeverity.HIGH,
        estimated_impact="Impact test",
    )
    executed = SupervisedActionEngine.approve_and_execute(
        envelope=envelope,
        supervisor_identity="CHIEF_SECURITY_OFFICER",
        secret_key=secret,
        record_to_ledger=False,
    )

    # 1. Verification succeeds with authentic envelope and correct key
    assert SupervisedActionEngine.verify_audit_signature(executed, secret_key=secret) is True

    # 2. Rejection with incorrect key
    assert SupervisedActionEngine.verify_audit_signature(executed, secret_key="wrong_enclave_key") is False

    # 3. Rejection if supervisor identity was modified after signing
    tampered_identity_env = deepcopy(executed)
    tampered_identity_env.supervisor_identity = "ATTACKER_IMPERSONATOR"
    assert SupervisedActionEngine.verify_audit_signature(tampered_identity_env, secret_key=secret) is False

    # 4. Rejection if timestamp was forged
    tampered_ts_env = deepcopy(executed)
    tampered_ts_env.approval_timestamp = executed.approval_timestamp + 3600
    assert SupervisedActionEngine.verify_audit_signature(tampered_ts_env, secret_key=secret) is False

    # 5. Rejection if payload digest was modified
    tampered_digest_env = deepcopy(executed)
    tampered_digest_env.payload_sha256 = "0" * 64
    assert SupervisedActionEngine.verify_audit_signature(tampered_digest_env, secret_key=secret) is False


def test_immutable_audit_ledger_chaining_and_tamper_detection():
    """
    [P3 Audit / Forensics Test] Verifies append-only block creation, SHA-256 Merkle block chaining,
    and deterministic detection of corrupted or altered historical blocks.
    """
    from src.protocol.audit_ledger import AuditLedger

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        tmp_ledger_path = tmp.name

    try:
        ledger = AuditLedger(file_path=tmp_ledger_path)
        # Genesis block verification
        assert ledger.get_block_count() == 1
        genesis = ledger.get_last_block()
        assert genesis["block_height"] == 0
        assert genesis["prev_block_hash"] == "0" * 64

        prev_hash = genesis["block_hash"]
        # Record 3 distinct action envelopes
        for i in range(1, 4):
            env = SupervisedActionEngine.propose_action(
                action_id=f"act_ledger_{i}",
                target_system=f"scada.node_{i}",
                command="ISOLATE",
                parameters={"subsystem": i},
                severity=ActionSeverity.HIGH,
                estimated_impact="Ledger verification test",
            )
            executed = SupervisedActionEngine.approve_and_execute(
                envelope=env,
                supervisor_identity=f"OPERATOR_LEDGER_{i}",
                record_to_ledger=False,
            )
            block = ledger.record_action(executed, auth_method="BIOMETRIC_TOUCH_ID")
            assert block["block_height"] == i
            assert block["prev_block_hash"] == prev_hash
            prev_hash = block["block_hash"]

        assert ledger.get_block_count() == 4
        is_valid, count, err = ledger.verify_ledger_integrity()
        assert is_valid is True
        assert count == 4
        assert err is None

        # Red-Team Attack: Simulate an intruder tampering with block 1 on disk
        with open(tmp_ledger_path, "r") as f:
            lines = f.readlines()

        # Tamper with the parameters in block 1
        b1 = json.loads(lines[1])
        b1["parameters"]["malicious_backdoor"] = "PWNED"
        lines[1] = json.dumps(b1) + "\n"

        with open(tmp_ledger_path, "w") as f:
            f.writelines(lines)

        # Integrity verification must catch the tamper at block 1
        is_valid_after_tamper, tamper_idx, tamper_err = ledger.verify_ledger_integrity()
        assert is_valid_after_tamper is False
        assert tamper_idx == 1
        assert "Tampered block detected" in tamper_err

    finally:
        if os.path.exists(tmp_ledger_path):
            os.remove(tmp_ledger_path)


def test_threading_concurrency_and_action_id_isolation():
    """
    [P2 Concurrency Test] Verifies that multiple concurrent actions are safely processed
    in isolated memory slots without TOCTOU race conditions.
    """
    def simulate_concurrent_action(idx: int):
        env = SupervisedActionEngine.propose_action(
            action_id=f"concurrent_act_{idx}",
            target_system=f"scada.subsystem_{idx}",
            command=f"THROTTLE_{idx}",
            parameters={"valve": idx, "rate": 50 + idx},
            severity=ActionSeverity.HIGH,
            estimated_impact="Concurrency test",
        )
        approved = SupervisedActionEngine.approve_and_execute(
            envelope=env,
            supervisor_identity=f"SUPERVISOR_THREAD_{idx}",
            record_to_ledger=False,
        )
        return approved

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(simulate_concurrent_action, i) for i in range(5)]
        results = [f.result() for f in futures]

    assert len(results) == 5
    for i, res in enumerate(results):
        assert res.payload.action_id == f"concurrent_act_{i}"
        assert res.status == ActionStatus.EXECUTED
        assert res.supervisor_identity == f"SUPERVISOR_THREAD_{i}"
        assert SupervisedActionEngine.verify_audit_signature(res) is True


if __name__ == "__main__":
    test_suite = [
        ("Cryptographic Integrity & HMAC Sealing", test_supervised_action_cryptographic_integrity),
        ("Canonical JSON Hash Determinism", test_canonical_json_hash_determinism),
        ("[HACK] MITM Financial Parameter Injection", test_hack_financial_parameter_injection),
        ("[HACK] SCADA Target Subsystem Hijacking", test_hack_scada_target_hijacking),
        ("[HACK] Command Escalation & Severity Downgrade", test_hack_command_escalation_and_severity_downgrade),
        ("[HACK] Stealth Rollback Poisoning Attack", test_hack_rollback_poisoning_attack),
        ("[HACK] Forged SHA-256 Digest Swap", test_hack_forged_sha256_signature_swap),
        ("[HACK] Replay Attack / Double Execution", test_hack_replay_attack_double_execution),
        ("[HACK] Zero-Trust Anonymous Identity Bypass", test_hack_zero_trust_anonymous_supervisor_bypass),
        ("Deterministic Rollback & Irreversible Guards", test_deterministic_rollback_and_irreversible_guard),
        ("[ERROR HANDLING] Meta Quota Exhaustion (HTTP 429)", test_meta_api_quota_exhausted_error_handling),
        ("[ERROR HANDLING] Network Disconnection / Offline", test_meta_api_network_connection_error_handling),
        ("Multi-Agent Llama 3.2 Vision & Risk Pipeline", test_full_orchestrator_pipeline),
        ("FastAPI Microservice & HTTP 400 Tamper Gate", test_fastapi_rest_endpoints_and_tamper_rejection),
        ("[P0 CRYPTO] Real HMAC-SHA256 Enclave Verification & Anti-Tamper", test_real_hmac_cryptographic_verification_and_tamper_rejection),
        ("[P3 LEDGER] Immutable Forensic Block Chaining & Disk Integrity", test_immutable_audit_ledger_chaining_and_tamper_detection),
        ("[P2 CONCURRENCY] Thread-Safe Multi-Action Envelope Isolation", test_threading_concurrency_and_action_id_isolation),
    ]

    print("\n======================================================================")
    print("🛡️  OMNESIGHT SENTINEL — SECURITY, RED-TEAM & UNIT TEST SUITE")
    print("======================================================================")
    passed = 0
    for label, fn in test_suite:
        fn()
        passed += 1
        print(f"  ✓ [PASS] {label} ({fn.__name__})")
    print("----------------------------------------------------------------------")
    print(f"✅ ALL {passed}/{len(test_suite)} SECURITY & FUNCTIONAL TESTS PASSED SUCCESSFULLY!")
    print("======================================================================\n")
