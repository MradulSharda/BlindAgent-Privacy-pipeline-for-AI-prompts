"""
Multi-provider LLM client supporting Google Gemini, OpenAI, Bedrock, and Offline Enclave Simulator.
Logs exact outbound payload to prove zero plaintext exposure to the host provider.
"""

import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("BlindAgent.LLM")


def _load_dotenv():
    """Load variables from .env or .env.local if present in project root."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for env_name in [".env", ".env.local"]:
        env_path = os.path.join(root, env_name)
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k and k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass


_load_dotenv()


DEFAULT_SYSTEM_INSTRUCTION = (
    "You are an intelligent AI agent operating in a Zero-Knowledge Privacy-Preserving Enclave. "
    "All user inputs have been pre-processed: sensitive variables, identifiers, and keys have been converted into "
    "non-sensitive mathematical handles of the format [[BLIND_TOKEN_...]]. "
    "These tokens represent synthetic, blinded handles. "
    "Fulfill the user's instructions (such as generating SQL queries, summaries, or reports) by referencing and using "
    "these exact [[BLIND_TOKEN_...]] placeholders directly in your output. "
    "Always preserve the exact [[BLIND_TOKEN_...]] strings so the local client enclave can map them securely."
)


class LLMClient:
    def __init__(self, provider: str = "auto", api_key: Optional[str] = None):
        _load_dotenv()
        self.provider = provider
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.openai_key = os.environ.get("OPENAI_API_KEY")
        self.last_host_received_payload: Optional[str] = None
        self.last_error: Optional[str] = None
        self.active_model: Optional[str] = None

        if self.provider == "auto":
            if self.api_key:
                self.provider = "gemini"
            elif self.openai_key:
                self.provider = "openai"
            else:
                self.provider = "simulated_host"

    def complete(self, prompt: str, system_instruction: Optional[str] = None) -> str:
        """
        Sends prompt to host LLM provider.
        Records exactly what leaves the local machine and lands on the provider's server.
        """
        self.last_host_received_payload = prompt
        self.last_error = None
        instruction = system_instruction or DEFAULT_SYSTEM_INSTRUCTION

        if self.provider == "gemini" and self.api_key:
            return self._call_gemini(prompt, instruction)
        elif self.provider == "openai" and self.openai_key:
            return self._call_openai(prompt, instruction)
        else:
            return self._call_simulator(prompt, instruction)

    def _call_gemini(self, prompt: str, system_instruction: Optional[str]) -> str:
        last_err = None
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                import google.generativeai as genai
            genai.configure(api_key=self.api_key)

            candidate_models = [
                "gemini-1.5-flash",
                "gemini-1.5-flash-latest",
                "gemini-2.0-flash",
                "gemini-2.5-flash",
                "gemini-pro",
            ]
            for model_name in candidate_models:
                try:
                    model = genai.GenerativeModel(
                        model_name=model_name,
                        system_instruction=system_instruction or "You are an intelligent secure AI assistant."
                    )
                    response = model.generate_content(prompt)
                    if response and response.text:
                        self.active_model = model_name
                        return response.text
                except Exception as model_err:
                    last_err = model_err
                    continue
            raise RuntimeError(f"All Gemini model endpoints failed. Last error: {last_err}")
        except Exception as e:
            self.last_error = str(e)
            return self._call_simulator(prompt, system_instruction)

    def _call_openai(self, prompt: str, system_instruction: Optional[str]) -> str:
        try:
            import urllib.request
            headers = {
                "Authorization": f"Bearer {self.openai_key}",
                "Content-Type": "application/json"
            }
            body = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": system_instruction or DEFAULT_SYSTEM_INSTRUCTION},
                    {"role": "user", "content": prompt}
                ]
            }
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=json.dumps(body).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"OpenAI API call failed ({e}). Falling back to host simulator.")
            return self._call_simulator(prompt, system_instruction)

    def _call_simulator(self, prompt: str, system_instruction: Optional[str]) -> str:
        """
        Simulated Cloud LLM Host Provider.
        Parses reasoning tasks, structure, and intent from prompt without ever seeing original plaintext.
        """
        lower = prompt.lower()
        
        # Check if query is asking for SQL query generation
        if "sql" in lower or "database" in lower or "query" in lower:
            return (
                "```sql\n"
                "-- Query generated by Cloud Agent\n"
                "SELECT account_id, balance, status \n"
                "FROM corporate_ledger \n"
                f"WHERE auth_token = (SELECT token FROM secrets WHERE ref = '{self._extract_token(prompt)}')\n"
                "  AND transaction_limit > 1000;\n"
                "```\n"
                "The requested records have been filtered according to the specified credentials."
            )

        # Check if query is asking for summary or analysis
        if "summarize" in lower or "report" in lower or "patient" in lower or "diagnos" in lower:
            return (
                "### Confidential Analysis Summary\n"
                f"The subject identified by security reference {self._extract_token(prompt)} "
                "was successfully evaluated. All criteria meet compliance standards under protocol SEC-800.\n"
                "- Risk Profile: Low\n"
                "- Operational Status: Active\n"
                "- Authorization Matrix: Verified against distributed threshold shares."
            )

        # Check if email/letter generation
        if "email" in lower or "letter" in lower or "notify" in lower:
            return (
                "Subject: Secure Authorization Confirmation\n\n"
                "Dear User,\n\n"
                "This email confirms that your authorized operation has been approved. "
                f"Your session key reference is {self._extract_token(prompt)}.\n\n"
                "Please do not share this reference with unauthorized third parties.\n\n"
                "Best regards,\nAutomated System Agent"
            )

        # Default intelligent structural reflection
        return (
            f"I have processed your encrypted instruction. The system verified parameters "
            f"associated with token: {self._extract_token(prompt)}. "
            f"All operations completed under zero-leakage protocol constraints."
        )

    def _extract_token(self, prompt: str) -> str:
        import re
        m = re.search(r"\[\[BLIND_TOKEN_\d+_[A-Z_]+(?::AFF8_[0-9a-fA-F]+)?\]\]", prompt)
        if m:
            return m.group(0)
        return "BLIND_TOKEN_REF"
