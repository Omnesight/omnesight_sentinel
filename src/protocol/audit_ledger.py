"""
Omnesight Sovereign Sentinel — Immutable Append-Only Audit Ledger
Cryptographic SHA-256 Block Chaining for Sovereign Forensic Audits (SOC2 / ISO 27001 / IEC 62443)
"""

import os
import json
import time
import hashlib
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

LEDGER_DEFAULT_DIR = Path(__file__).resolve().parent.parent.parent / "data"
LEDGER_DEFAULT_PATH = LEDGER_DEFAULT_DIR / "audit_ledger.jsonl"


class AuditLedger:
    """
    Immutable, append-only, tamper-evident audit ledger.
    Every supervisory sign-off and SCADA actuation is cryptographically sealed
    into a chained SHA-256 block structure (Blockchain-style Merkle link).
    """

    _lock = threading.RLock()

    def __init__(self, file_path: Optional[str] = None):
        self.file_path = Path(file_path or os.getenv("SENTINEL_LEDGER_PATH", str(LEDGER_DEFAULT_PATH)))
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.file_path.exists() or self.file_path.stat().st_size == 0:
            self._init_genesis_block()

    def _init_genesis_block(self):
        """Initializes the immutable ledger with a sovereign genesis block if empty."""
        genesis_block = {
            "block_height": 0,
            "timestamp": "2026-10-30T00:00:00Z",
            "prev_block_hash": "0" * 64,
            "action_id": "GENESIS_SOVEREIGN_ROOT",
            "payload_hash": hashlib.sha256(b"OMNESIGHT_SENTINEL_GENESIS_ROOT_2026").hexdigest(),
            "target_system": "SOVEREIGN_GOVERNANCE_ROOT",
            "command": "INITIALIZE_IMMUTABLE_AUDIT_LEDGER",
            "parameters": {"protocol_version": "2026.1-llama-stack", "security_tier": "IEC-62443-TIER-1"},
            "supervisor": "SYSTEM_SOVEREIGN_ROOT",
            "auth_method": "ENCLAVE_ROOT_INIT",
            "audit_signature": "SOVEREIGN_GENESIS_SEAL_OMNESIGHT_2026",
        }
        genesis_hash = self.compute_block_hash(genesis_block)
        genesis_block["block_hash"] = genesis_hash

        with open(self.file_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(genesis_block) + "\n")

    @staticmethod
    def compute_block_hash(block: Dict[str, Any]) -> str:
        """
        Computes the canonical SHA-256 digest of an audit block.
        The block_hash field itself is excluded from computation.
        """
        raw = {k: v for k, v in block.items() if k != "block_hash"}
        canonical = json.dumps(raw, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get_last_block(self) -> Dict[str, Any]:
        """Returns the most recent block recorded in the ledger."""
        with self._lock:
            if not self.file_path.exists():
                self._init_genesis_block()
            last_line = None
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
            if last_line:
                return json.loads(last_line)
            self._init_genesis_block()
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.loads(f.readline().strip())

    def record_action(
        self,
        envelope: Any,
        auth_method: str = "BIOMETRIC_TOUCH_ID",
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Cryptographically seals an approved SupervisedActionEnvelope into the ledger.
        Chains with the previous block hash to ensure tamper-evidence.
        """
        with self._lock:
            last_block = self.get_last_block()
            block_height = last_block["block_height"] + 1
            prev_block_hash = last_block["block_hash"]

            # Extract fields from envelope safely (supports BaseModel or dict)
            payload = getattr(envelope, "payload", None)
            if payload is None and isinstance(envelope, dict):
                payload = envelope.get("payload", {})

            action_id = getattr(payload, "action_id", None) or (payload.get("action_id") if isinstance(payload, dict) else "UNKNOWN_ACT")
            payload_hash = getattr(envelope, "payload_sha256", None) or (envelope.get("payload_sha256") if isinstance(envelope, dict) else "")
            target = getattr(payload, "target_system", None) or (payload.get("target_system") if isinstance(payload, dict) else "")
            cmd = getattr(payload, "command", None) or (payload.get("command") if isinstance(payload, dict) else "")
            params = getattr(payload, "parameters", None) or (payload.get("parameters") if isinstance(payload, dict) else {})
            supervisor = getattr(envelope, "supervisor_identity", None) or (envelope.get("supervisor_identity") if isinstance(envelope, dict) else "UNKNOWN")
            sig = getattr(envelope, "audit_signature", None) or (envelope.get("audit_signature") if isinstance(envelope, dict) else "")
            ts = getattr(envelope, "approval_timestamp", None) or time.time()
            ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

            new_block = {
                "block_height": block_height,
                "timestamp": ts_str,
                "prev_block_hash": prev_block_hash,
                "action_id": action_id,
                "payload_hash": payload_hash,
                "target_system": target,
                "command": cmd,
                "parameters": params,
                "supervisor": supervisor,
                "auth_method": auth_method,
                "audit_signature": sig,
            }
            if notes:
                new_block["notes"] = notes

            block_hash = self.compute_block_hash(new_block)
            new_block["block_hash"] = block_hash

            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(new_block) + "\n")

            return new_block

    def verify_ledger_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """
        Verifies the cryptographic chain across the entire ledger.
        Returns:
            (is_valid, block_count, error_description)
        """
        with self._lock:
            if not self.file_path.exists():
                return False, 0, "Ledger file missing"

            blocks: List[Dict[str, Any]] = []
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        blocks.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        return False, len(blocks), f"Malformed JSON at line {line_idx}: {str(e)}"

            if not blocks:
                return False, 0, "Ledger is empty"

            expected_prev_hash = "0" * 64
            for idx, block in enumerate(blocks):
                # Verify height continuity
                if block.get("block_height") != idx:
                    return False, idx, f"Block height mismatch at block {idx}: expected {idx}, got {block.get('block_height')}"

                # Verify chain linkage
                if idx == 0:
                    if block.get("prev_block_hash") != expected_prev_hash:
                        return False, 0, "Genesis block prev_hash is corrupted"
                else:
                    if block.get("prev_block_hash") != expected_prev_hash:
                        return False, idx, f"Chain broken at block {idx}: prev_block_hash does not match hash of block {idx - 1}"

                # Verify self block hash
                computed_hash = self.compute_block_hash(block)
                if computed_hash != block.get("block_hash"):
                    return False, idx, f"Tampered block detected at height {idx}: expected {computed_hash}, recorded {block.get('block_hash')}"

                expected_prev_hash = block.get("block_hash")

            return True, len(blocks), None

    def get_recent_blocks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns the most recent N blocks in reverse chronological order."""
        with self._lock:
            if not self.file_path.exists():
                return []
            lines = []
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        lines.append(line)
            recent = lines[-limit:]
            return [json.loads(l) for l in reversed(recent)]

    def get_block_count(self) -> int:
        """Returns total blocks in the ledger."""
        with self._lock:
            if not self.file_path.exists():
                return 0
            count = 0
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        count += 1
            return count
