"""
Omnesight Sentinel — Financial & Contractual Risk Agent
Powered by Meta Llama 3.2 via Llama Stack
"""

from typing import Dict, Any
from src.llama_stack.client import LlamaStackClientAdapter

class FinancialRiskAgent:
    def __init__(self, client: LlamaStackClientAdapter):
        self.client = client
        self.name = "Omnesight Financial Risk Sentinel"

    def assess_liability(self, physical_incident: Dict[str, Any], contract_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates Take-or-Pay risk and SBLC exposure.
        """
        return self.client.evaluate_contractual_liability(
            physical_anomaly=physical_incident,
            contract_data=contract_data,
            model="meta-llama/Llama-3.2-3B-Instruct"
        )
