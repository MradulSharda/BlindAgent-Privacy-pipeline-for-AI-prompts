"""
End-to-End Secure Enclave AI Pipeline.
Orchestrates client-side mathematical blinding, cloud LLM execution, and local unblinding.
"""

import time
from typing import Dict, Any, Optional
from dataclasses import dataclass
from blindagent.blinder import SemanticBlinder
from blindagent.llm_client import LLMClient


@dataclass
class PipelineResult:
    user_input: str
    wire_payload: str
    host_raw_response: str
    final_output: str
    execution_time_ms: float
    metrics: Dict[str, Any]
    provider_used: str
    shares_generated: Dict[str, list]


class BlindPipeline:
    def __init__(self, sss_threshold: int = 3, sss_total: int = 5, provider: str = "auto", api_key: Optional[str] = None):
        self.blinder = SemanticBlinder(sss_threshold=sss_threshold, sss_total=sss_total)
        self.llm = LLMClient(provider=provider, api_key=api_key)

    def execute(self, prompt: str, system_prompt: Optional[str] = None) -> PipelineResult:
        start_time = time.perf_counter()

        # Step 1: Client Enclave - Mathematical Blinding & SSS generation
        blinded_prompt, metrics = self.blinder.blind_prompt(prompt)

        # Step 2: Transmit ONLY the blinded payload to cloud LLM host
        host_response = self.llm.complete(blinded_prompt, system_instruction=system_prompt)

        # Step 3: Client Enclave - Local Unblinding and Reconstruction
        unblinded_response = self.blinder.unblind_response(host_response)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        shares_dict = {
            token: entity.shares
            for token, entity in self.blinder.vault.items()
        }

        return PipelineResult(
            user_input=prompt,
            wire_payload=blinded_prompt,
            host_raw_response=host_response,
            final_output=unblinded_response,
            execution_time_ms=round(elapsed_ms, 2),
            metrics=metrics,
            provider_used=self.llm.provider,
            shares_generated=shares_dict
        )
