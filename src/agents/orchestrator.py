"""
Omnesight Sentinel — Master Orchestrator
Coordinates Multimodal Vision, Telemetry, and Contractual Risk into a Supervised Action.
"""

from typing import Dict, Any
from src.llama_stack.client import LlamaStackClientAdapter
from src.agents.telemetry_vision_agent import TelemetryVisionAgent
from src.agents.financial_risk_agent import FinancialRiskAgent
from src.protocol.supervised_action import SupervisedActionEngine, SupervisedActionEnvelope, ActionSeverity

class SentinelMasterOrchestrator:
    def __init__(self, client: LlamaStackClientAdapter):
        self.client = client
        self.vision_agent = TelemetryVisionAgent(client)
        self.financial_agent = FinancialRiskAgent(client)

    def process_system_state(
        self,
        scada_data: Dict[str, Any],
        vision_data: Dict[str, Any],
        contract_data: Dict[str, Any]
    ) -> SupervisedActionEnvelope:
        # Step 1: Multimodal Vision & SCADA Analysis (Llama 3.2 Vision)
        physical_diagnosis = self.vision_agent.process_incident(scada_data, vision_data)

        # Step 2: Financial Liability Synthesis (Llama 3.2 Text)
        financial_assessment = self.financial_agent.assess_liability(physical_diagnosis, contract_data)

        # Step 3: Formulate Deterministic Supervised Action Protocol Payload
        recommended = physical_diagnosis.get("recommended_action", {})
        action_id = f"act_elps_{int(scada_data.get('timestamp', 0))}_safe"
        
        impact_summary = (
            f"Physical: {physical_diagnosis.get('root_cause_diagnosis')} | "
            f"Financial Protection: Prevents ${financial_assessment.get('estimated_loss_prevented_usd'):,.0f} USD "
            f"in Take-or-Pay liquidated damages with {financial_assessment.get('counterparty')}."
        )

        envelope = SupervisedActionEngine.propose_action(
            action_id=action_id,
            target_system=recommended.get("target_system", "scada.pipeline.escravos_lagos.valve_12"),
            command=recommended.get("command", "THROTTLE_INFLOW_TO_65_PERCENT"),
            parameters=recommended.get("parameters", {}),
            severity=ActionSeverity.CRITICAL,
            estimated_impact=impact_summary,
            rollback_command=recommended.get("rollback_command"),
            rollback_parameters=recommended.get("rollback_parameters"),
        )

        return envelope
