"""
Omnesight Sentinel — Telemetry & Vision Agent
Powered by Meta Llama 3.2 Vision (11B/90B) via Llama Stack
"""

from typing import Dict, Any
from src.llama_stack.client import LlamaStackClientAdapter

class TelemetryVisionAgent:
    def __init__(self, client: LlamaStackClientAdapter):
        self.client = client
        self.name = "Omnesight Telemetry & Vision Sentinel"

    def process_incident(self, scada_data: Dict[str, Any], vision_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cross-correlates SCADA data and optical/thermal inspection.
        """
        return self.client.analyze_multimodal_telemetry(
            image_metadata=vision_data,
            scada_telemetry=scada_data,
            model="meta-llama/Llama-3.2-11B-Vision-Instruct"
        )
