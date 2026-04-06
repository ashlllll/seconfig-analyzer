"""
llm_explainer.py
~~~~~~~~~~~~~~~~
LLM-based explanation service for SecConfig Analyzer.

Architecture constraints (by design)
-------------------------------------
* The LLM is **disabled by default** and must be explicitly enabled.
* It only receives *output* from the deterministic analysis — never raw
  configuration file content.
* It cannot modify, trigger, or influence any security decision.
* All API errors are caught and returned as user-friendly messages.

Supported backends
------------------
* ``"ollama"``  — Local Ollama server (default, free, no API key needed).
* ``"openai"``  — OpenAI API (requires OPENAI_API_KEY).
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Optional

from src.utils.logger import get_logger
from src.core.explainer.prompt_builder import DynamicPromptBuilder

log = get_logger(__name__)

OLLAMA_DEFAULT_URL   = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "llama3.2:1b"

ReportContext = dict[str, Any]


def check_ollama_status(base_url: str = OLLAMA_DEFAULT_URL) -> tuple[bool, str]:
    try:
        import requests
        resp = requests.get(f"{base_url}/api/tags", timeout=3)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            return True, f"Ollama running · {len(models)} model(s) available"
        return False, f"Ollama responded with HTTP {resp.status_code}"
    except Exception as exc:
        return False, f"Ollama not reachable: {exc}"


class LLMExplainerService:

    def __init__(
        self,
        enabled: bool = False,
        backend: str = "ollama",
        api_key: Optional[str] = None,
        ollama_url: str = OLLAMA_DEFAULT_URL,
        model: str = OLLAMA_DEFAULT_MODEL,
        temperature: float = 0.8,
        max_tokens: int = 500,
        presence_penalty: float = 0.6,
        frequency_penalty: float = 0.6,
    ) -> None:
        self.enabled           = enabled
        self.backend           = backend.lower()
        self.ollama_url        = ollama_url.rstrip("/")
        self.model             = model
        self.temperature       = temperature
        self.max_tokens        = max_tokens
        self.presence_penalty  = presence_penalty
        self.frequency_penalty = frequency_penalty
        self._api_key          = api_key or os.getenv("OPENAI_API_KEY")
        self._history: list[dict[str, str]] = []
        self._prompt_builder = DynamicPromptBuilder()

        if self.enabled and self.backend == "ollama":
            ok, msg = check_ollama_status(self.ollama_url)
            if not ok:
                log.warning("LLM Explainer: %s", msg)

    def explain(
        self,
        report_context: ReportContext,
        user_query: str,
        user_background: str = "junior_dev",
    ) -> str:
        if not self.enabled:
            return (
                "🔒 **LLM Explainer is disabled.**\n\n"
                "Enable it via the sidebar toggle to ask questions about the analysis.\n"
                "Note: the LLM only has access to *analysis outputs* — never your raw config files."
            )

        context = {**report_context, "user_background": user_background}
        avoid_phrases = self._prompt_builder.extract_overused_phrases(self._history)
        prompt = self._prompt_builder.build(
            context=context,
            user_query=user_query,
            avoid_phrases=avoid_phrases,
        )

        if self.backend == "ollama":
            response_text = self._call_ollama(prompt)
        else:
            response_text = self._call_openai(prompt)

        self._history.append({"query": user_query, "response": response_text})
        return response_text

    @staticmethod
    def build_context(
        config_file_name: str,
        issues: list[Any],
        fixes: list[Any],
        initial_risk: float,
        final_risk: float,
        risk_reduction_pct: float,
    ) -> ReportContext:
        severity_counts: dict[str, int] = {}
        issues_summary: list[dict[str, Any]] = []

        for issue in issues:
            sev = getattr(issue, "severity", "unknown").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for issue in issues[:5]:
            issues_summary.append({
                "rule_id":     getattr(issue, "rule_id", ""),
                "title":       getattr(issue, "title", "Unknown"),
                "severity":    getattr(issue, "severity", ""),
                "category":    getattr(issue, "category", ""),
                "line_number": getattr(issue, "line_number", 0),
                "nist":        getattr(issue, "nist_function", ""),
            })

        auto_fixes   = sum(1 for f in fixes if getattr(f, "fix_type", "") == "automated")
        manual_fixes = sum(1 for f in fixes if getattr(f, "fix_type", "") == "manual")

        return {
            "config_file":     config_file_name,
            "total_issues":    len(issues),
            "critical_count":  severity_counts.get("critical", 0),
            "high_count":      severity_counts.get("high", 0),
            "medium_count":    severity_counts.get("medium", 0),
            "low_count":       severity_counts.get("low", 0),
            "severity_counts": severity_counts,
            "issues_summary":  issues_summary,
            "total_fixes":     len(fixes),
            "auto_fixes":      auto_fixes,
            "manual_fixes":    manual_fixes,
            "risk_score":      initial_risk,
            "final_risk":      final_risk,
            "risk_reduction":  risk_reduction_pct,
            "generated_at":    datetime.now().isoformat(),
        }

    def clear_history(self) -> None:
        self._history.clear()

    @property
    def conversation_history(self) -> list[dict[str, str]]:
        return list(self._history)

    def _call_ollama(self, prompt: dict[str, str]) -> str:
        try:
            import requests
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user",   "content": prompt["user"]},
                ],
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                },
            }
            resp = requests.post(
                f"{self.ollama_url}/api/chat",
                json=payload,
                timeout=120,
            )
            resp.raise_for_status()
            text = resp.json()["message"]["content"]
            return text.strip()

        except Exception as exc:
            log.error("Ollama call failed: %s", exc)
            return (
                f"⚠️ **Could not reach Ollama.**\n\nError: `{exc}`\n\n"
                "**Quick fixes:**\n"
                "1. Run `ollama serve` in a terminal\n"
                f"2. Check model is pulled: `ollama pull {self.model}`\n\n"
                "The deterministic analysis results above are unaffected."
            )

    def _call_openai(self, prompt: dict[str, str]) -> str:
        if not self._api_key:
            return "⚠️ No OpenAI API key. Switch to Ollama backend instead."
        try:
            import openai
            client = openai.OpenAI(api_key=self._api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user",   "content": prompt["user"]},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return (response.choices[0].message.content or "").strip()
        except Exception as exc:
            return f"⚠️ OpenAI error: {exc}"