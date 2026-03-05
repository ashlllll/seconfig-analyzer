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
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Optional

from src.utils.logger import get_logger
from src.core.explainer.prompt_builder import DynamicPromptBuilder

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Type alias for the analysis report context
# ---------------------------------------------------------------------------
ReportContext = dict[str, Any]


class LLMExplainerService:
    """
    Post-analysis natural language explanation service.

    Parameters
    ----------
    enabled:
        Whether the service is active.  Defaults to ``False``.
    api_key:
        OpenAI API key.  Falls back to the ``OPENAI_API_KEY`` environment
        variable when not provided.
    model:
        OpenAI model to use (default ``"gpt-4"``).
    temperature:
        Controls output randomness (higher = more varied).
    max_tokens:
        Maximum tokens in the LLM response.
    """

    def __init__(
        self,
        enabled: bool = False,
        api_key: Optional[str] = None,
        model: str = "gpt-4",
        temperature: float = 0.8,
        max_tokens: int = 500,
        presence_penalty: float = 0.6,
        frequency_penalty: float = 0.6,
    ) -> None:
        self.enabled           = enabled
        self.model             = model
        self.temperature       = temperature
        self.max_tokens        = max_tokens
        self.presence_penalty  = presence_penalty
        self.frequency_penalty = frequency_penalty

        # Resolve API key (explicit → env var)
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")

        # Conversation history for diversity tracking
        self._history: list[dict[str, str]] = []

        # Prompt builder
        self._prompt_builder = DynamicPromptBuilder()

        if self.enabled and not self._api_key:
            log.warning(
                "LLM Explainer is enabled but no API key was provided. "
                "Set OPENAI_API_KEY or pass api_key= explicitly."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def explain(
        self,
        report_context: ReportContext,
        user_query: str,
        user_background: str = "junior_dev",
    ) -> str:
        """
        Generate a natural-language explanation for *user_query*.

        Parameters
        ----------
        report_context:
            Dictionary produced by :meth:`build_context`.
        user_query:
            The user's question or request.
        user_background:
            One of ``"junior_dev"`` | ``"manager"`` | ``"security_expert"``.

        Returns
        -------
        str
            Explanation text (or a fallback message if disabled/unavailable).
        """
        if not self.enabled:
            return (
                "🔒 **LLM Explainer is disabled.**\n\n"
                "Enable it via Settings to ask questions about the analysis results.\n"
                "Note: The LLM only has access to *analysis outputs* — never your raw config files."
            )

        if not self._api_key:
            return (
                "⚠️ **LLM Explainer is enabled but no API key is configured.**\n\n"
                "Please set the `OPENAI_API_KEY` environment variable and restart the app."
            )

        # Merge user background into context
        context = {**report_context, "user_background": user_background}

        # Determine phrases to avoid (diversity enforcement)
        avoid_phrases = self._prompt_builder.extract_overused_phrases(self._history)

        # Build prompt
        prompt = self._prompt_builder.build(
            context=context,
            user_query=user_query,
            avoid_phrases=avoid_phrases,
        )

        # Call LLM
        response_text = self._call_llm(prompt)

        # Record in history
        self._history.append({"query": user_query, "response": response_text})

        return response_text

    # ------------------------------------------------------------------

    @staticmethod
    def build_context(
        config_file_name: str,
        issues: list[Any],          # List[SecurityIssue]
        fixes: list[Any],           # List[SecurityFix]
        initial_risk: float,
        final_risk: float,
        risk_reduction_pct: float,
    ) -> ReportContext:
        """
        Construct the context dictionary passed to :meth:`explain`.

        This method acts as a data-minimisation layer: only summary statistics
        and sanitised issue metadata are included — **no raw config content**.

        Parameters
        ----------
        config_file_name:
            Name of the analysed configuration file (display only).
        issues:
            Full list of ``SecurityIssue`` objects.
        fixes:
            Full list of ``SecurityFix`` objects.
        initial_risk:
            Monte Carlo mean risk score before remediation (0–100).
        final_risk:
            Monte Carlo mean risk score after remediation (0–100).
        risk_reduction_pct:
            Percentage reduction in risk score.

        Returns
        -------
        dict
            Safe context dictionary for the prompt builder.
        """
        # Group issues by severity for the summary
        severity_counts: dict[str, int] = {}
        issues_summary: list[dict[str, Any]] = []

        for issue in issues:
            sev = getattr(issue, "severity", "unknown").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Include only the first 5 issues in the summary (data minimisation)
        for issue in issues[:5]:
            issues_summary.append(
                {
                    "rule_id":     getattr(issue, "rule_id", ""),
                    "title":       getattr(issue, "title", "Unknown"),
                    "severity":    getattr(issue, "severity", ""),
                    "category":    getattr(issue, "category", ""),
                    "line_number": getattr(issue, "line_number", 0),
                    "nist":        getattr(issue, "nist_function", ""),
                }
            )

        auto_fixes   = sum(1 for f in fixes if getattr(f, "fix_type", "") == "automated")
        manual_fixes = sum(1 for f in fixes if getattr(f, "fix_type", "") == "manual")

        return {
            "config_file":      config_file_name,
            "total_issues":     len(issues),
            "critical_count":   severity_counts.get("critical", 0),
            "high_count":       severity_counts.get("high", 0),
            "medium_count":     severity_counts.get("medium", 0),
            "low_count":        severity_counts.get("low", 0),
            "severity_counts":  severity_counts,
            "issues_summary":   issues_summary,
            "total_fixes":      len(fixes),
            "auto_fixes":       auto_fixes,
            "manual_fixes":     manual_fixes,
            "risk_score":       initial_risk,
            "final_risk":       final_risk,
            "risk_reduction":   risk_reduction_pct,
            "generated_at":     datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------

    def clear_history(self) -> None:
        """Reset conversation history (e.g. when a new file is uploaded)."""
        self._history.clear()
        log.debug("LLM conversation history cleared.")

    @property
    def conversation_history(self) -> list[dict[str, str]]:
        """Read-only view of the conversation history."""
        return list(self._history)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _call_llm(self, prompt: dict[str, str]) -> str:
        """
        Dispatch to the OpenAI API and return the response text.

        Falls back gracefully on any exception.
        """
        try:
            import openai  # lazy import – not required unless LLM is enabled

            client = openai.OpenAI(api_key=self._api_key)

            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user",   "content": prompt["user"]},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                presence_penalty=self.presence_penalty,
                frequency_penalty=self.frequency_penalty,
            )

            text = response.choices[0].message.content or ""
            log.debug("LLM response received (%d chars).", len(text))
            return text.strip()

        except ImportError:
            msg = (
                "The `openai` package is not installed. "
                "Run `pip install openai` to enable LLM explanations."
            )
            log.error(msg)
            return f"⚠️ {msg}"

        except Exception as exc:  # broad catch – LLM errors must not crash the app
            log.error("LLM API call failed: %s", exc)
            return (
                f"⚠️ **LLM explanation unavailable.**\n\n"
                f"Error: {exc}\n\n"
                "The deterministic analysis results above are unaffected."
            )
