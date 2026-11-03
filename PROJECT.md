# Omnesight Sentinel — System Specification & Architectural Deep-Dive
### Reference Document: Supervised Action Protocol (SAP), Threat Models & Multi-Agent Orchestration

---

## 1. Context & Industrial Motivation

### 1.1 The Frontier of Physical AI
Autonomous AI agents are transitioning from digital software sandboxes to **cyber-physical systems** (power distribution grids, offshore gas pipelines, refinery cracking towers, and automated financial settlement networks). In these mission-critical domains, a single hallucinated parameter or unverified execution can lead to catastrophic consequences:
* Environmental disasters and pipeline ruptures.
* Equipment destruction costing tens of millions of dollars.
* Acute contractual default under Take-or-Pay gas supply agreements ($300k+ per hour in liquidated damages).

### 1.2 The Determinism Deficit in Modern LLMs
Large Language Models are probabilistic token predictors by design. They lack:
1. **Cryptographic Verifiability:** An LLM output cannot natively prove it was not altered in transit.
2. **Deterministic Rollback Guarantees:** A conversational model cannot safely reverse an actuation if downstream pressure spikes abnormally.
3. **Hardware-Enforced Supervisory Gating:** Generative models lack physical Human-in-the-Loop checkpoints compliant with industrial security standards like **IEC-62443** and **SOC2 Type II**.

**Omnesight Sentinel bridges this determinism deficit** by wrapping Meta Llama 3.2 models in a zero-trust, cryptographically verified execution boundary called the **Supervised Action Protocol (SAP)**.

---

## 2. Multi-Agent Orchestration Architecture

Sentinel deploys a hierarchical, specialized agent topology built natively on the **Meta Llama Stack Runtime**:

```
                              [ Physical SCADA Telemetry ]
                              [ FLIR Thermography Feeds  ]
                              [ Enterprise GSA Contracts ]
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                       META LLAMA STACK AGENT RUNTIME                                │
│                                                                                     │
│  ┌───────────────────────────────┐         ┌─────────────────────────────────────┐  │
│  │   TelemetryVisionAgent        │         │      FinancialRiskAgent             │  │
│  │   • Llama 3.2 Vision (11B)    │         │      • Llama 3.2 Text (70B) / Kiam  │  │
│  │   • Optical Flare Pinpointing │         │      • Contractual Penalty Parsing  │  │
│  │   • Differential Pressure Δ   │         │      • Force Majeure Timers         │  │
│  └──────────────┬────────────────┘         └──────────────────┬──────────────────┘  │
│                 │                                             │                     │
│                 └──────────────────────┬──────────────────────┘                     │
│                                        ▼                                            │
│                      ┌───────────────────────────────────┐                          │
│                      │      Master Orchestrator          │                          │
│                      │      • Cross-Domain Synthesis     │                          │
│                      │      • Remediation Action Payload │                          │
│                      └─────────────────┬─────────────────┘                          │
└────────────────────────────────────────┼────────────────────────────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                    SUPERVISED ACTION PROTOCOL (SAP) ENCLAVE                         │
│                                                                                     │
│  ┌─────────────────────────┐  ┌───────────────────────────┐  ┌───────────────────┐  │
│  │  Canonical JSON Normal. │  │  HMAC SHA-256 Digest Seal │  │ FIDO2 MFA Gating  │  │
│  │  Sort keys, no spacing  │  │  Digest: e3b0c44298fc...  │  │ Biometric / Token │  │
│  └─────────────────────────┘  └───────────────────────────┘  └───────────────────┘  │
└────────────────────────────────────────┬────────────────────────────────────────────┘
                                         ▼
                             [ Physical SCADA Actuator ]
                             [ Automated GSA Notice    ]
                             [ Immutable Audit Ledger  ]
```

### 2.1 Agent Specifications

#### Agent 1: `TelemetryVisionAgent`
* **Underlying Model:** Meta Llama 3.2 Vision (11B / 90B Multimodal).
* **Inputs:** 
  - Time-series SCADA sensor stream: Segment pressure (bar), mass flow rate (kg/s), vibration frequency (Hz), temperature delta (°C).
  - Optical/Infrared imagery: Subsea camera feeds (`CAM-ESC-0428-FLIR`).
* **Analytical Mandate:** Detect physical anomalies, isolate micro-fissures, cross-reference thermal bloom coordinates with pipeline kilometer markers, and recommend precise mechanical containment (e.g. throttling percentage).

#### Agent 2: `FinancialRiskAgent`
* **Underlying Model:** Meta Llama 3.2 Instruct (70B) / Sovereign Kiam MLOps.
* **Inputs:** 
  - Enterprise ERP data: Active Gas Sales Agreements (NNPC GSA 2024-C), delivery commitments, letters of credit (SBLC), hourly downtime penalties.
* **Analytical Mandate:** Quantify acute financial exposure in USD/hour, identify breach windows, and draft mandatory legal notices (*Force Majeure* under Article 14.2) to cap corporate liability.

#### Agent 3: `MasterOrchestrator`
* **Underlying Engine:** Llama Stack Agent Framework.
* **Analytical Mandate:** Synthesizes outputs from both agents into a single unified **Action Proposal Envelope**. It ensures the proposed mechanical containment does not violate legal or financial constraints.

---

## 3. Supervised Action Protocol (SAP) Specification

The Supervised Action Protocol is a deterministic, mathematically verifiable envelope that wraps any proposed action before it reaches actuators or financial networks.

### 3.1 The Action Envelope Data Structure
```json
{
  "action_id": "act_84920a_containment_01",
  "created_at": "2026-10-30T17:38:54Z",
  "severity": "CRITICAL",
  "directive": {
    "action": "THROTTLE_INFLOW_TO_65_PERCENT",
    "target_subsystem": "ELPS-VALVE-12",
    "rate_limit_m3_h": 18500,
    "bypass_route": "WEST-GRID-BYPASS-02"
  },
  "financial_context": {
    "contract_id": "NNPC-GSA-2024-C",
    "exposure_rate_hourly_usd": 320000.00,
    "max_daily_penalty_usd": 1280000.00,
    "force_majeure_notice_window_hours": 4
  },
  "rollback_directive": {
    "action": "RESTORE_INFLOW_TO_100_PERCENT",
    "target_subsystem": "ELPS-VALVE-12",
    "max_rollback_window_seconds": 3600
  },
  "payload_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "status": "AWAITING_SUPERVISOR_SIGNATURE"
}
```

### 3.2 Canonical JSON Normalization
To ensure mathematical determinism, the cryptographic digest is calculated over **Canonical JSON** (RFC 8785 standard):
$$\text{Digest} = \text{SHA-256}(\text{Canonicalize}(\text{Directive} \parallel \text{FinancialContext} \parallel \text{RollbackDirective}))$$
Keys are sorted lexicographically, whitespace is eliminated, and floating point representations are strictly normalized. This guarantees that `{"a": 1, "b": 2}` and `{"b": 2, "a": 1}` yield the identical cryptographic hash.

### 3.3 Zero-Trust Verification Rules
Before the action is executed:
1. **Re-computation Guard:** The supervisor gateway re-computes the SHA-256 digest independently from the payload bytes.
2. **Bit-Level Equality:** If $\text{Digest}_{\text{computed}} \neq \text{Digest}_{\text{payload}}$, execution is **immediately aborted** and an intrusion alert is logged.
3. **Supervisor Identity Clearance:** The operator must present valid cryptographic credentials (FIDO2 WebAuthn / hardware security key) matching authorized role permissions (e.g. `COO // SIGNER` with IEC-62443 Class-4 SCADA clearance).
4. **Anti-Replay Nonce:** Every action envelope possesses a monotonic timestamp and unique nonce. Replaying an already-approved action throws an instant `REPLAY_ATTACK_DETECTED` exception.

---

## 4. Threat Model & Red-Team Security Validation

Sentinel has been rigorously tested against a battery of **17 red-team attack scenarios** implemented in [`tests/test_sentinel.py`](tests/test_sentinel.py):

| Attack Vector | Attacker Objective | Sentinel Defense Mechanism | Result |
| :--- | :--- | :--- | :--- |
| **MITM Financial Tampering** | Attacker alters penalty liability from \$320k to \$3.2k to delay emergency dispatch. | SHA-256 digest re-computation fails immediately. Action rejected. | ✅ Defeated |
| **SCADA Target Hijacking** | Attacker redirects valve throttle from `ELPS-VALVE-12` to `MAIN-FEED-COMPRESSOR`. | Target mismatch detected during canonical serialization check. | ✅ Defeated |
| **Severity Downgrade** | Attacker downgrades incident severity from `CRITICAL` to `LOW`. | Severity field is part of the sealed payload envelope. Signature mismatch. | ✅ Defeated |
| **Rollback Poisoning** | Attacker tampers with the rollback directive to lock valves permanently. | Rollback sub-object is sealed under the master HMAC. Rollback rejected. | ✅ Defeated |
| **Signature Swap Attack** | Attacker swaps the valid digest with an arbitrary sha256 hash. | Gateway recalculates true canonical bytes hash; forged hash mismatch. | ✅ Defeated |
| **Replay / Double Execution** | Attacker replays a valid signed payload to force repeated valve closures. | Envelope status check prohibits re-approval of executed actions. | ✅ Defeated |
| **Anonymous Supervisor Bypass** | Attacker signs with unauthenticated or empty supervisor session. | Zero-Trust Gateway mandates non-null cryptographically authorized identity. | ✅ Defeated |

---

## 5. Economic & Operational Impact (ROI)

Using the Escravos-Lagos Pipeline System (ELPS) as our baseline enterprise case study:

* **Direct Pipeline Liability Avoided:**  
  $$\text{Savings} = 4 \text{ hours} \times \$320,000/\text{hr} = \mathbf{\$1,280,000\text{ USD}}$$
* **Physical Asset Integrity:**  
  Throttling inflow to 65% within 12 minutes prevents full flange blowout at Km 42.8, avoiding catastrophic subsea replacement costs estimated at **\$8,500,000 USD** and months of regional gas supply disruption.
* **Audit & Legal Compliance:**  
  Generates an indisputable, immutable audit log (`audit_ledger.jsonl`) for insurers, state regulators (NUPRC), and international commercial arbitrators.

---

## 6. Hackathon Evaluation Checklist

For judges evaluating Omnesight Sentinel:
- [x] **Native Meta Llama Stack Client:** Implemented in [`src/llama_stack/client.py`](src/llama_stack/client.py).
- [x] **Multimodal Llama 3.2 Vision Integration:** Implemented in [`src/agents/telemetry_vision_agent.py`](src/agents/telemetry_vision_agent.py).
- [x] **Deterministic Security Protocol:** Implemented in [`src/protocol/supervised_action.py`](src/protocol/supervised_action.py).
- [x] **17/17 Security & Unit Tests Passing:** Runnable via `python tests/test_sentinel.py`.
- [x] **Real-Time Operational Console:** Runnable via `python ui/console.py` on `http://localhost:9626`.

