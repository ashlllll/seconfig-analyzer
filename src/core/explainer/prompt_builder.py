"""
prompt_builder.py
~~~~~~~~~~~~~~~~~
Dynamic prompt construction for the LLM Explainer.

Design goals
------------
* Persona-aware  – tone adapts to user background (junior dev / manager / expert).
* Intent-aware   – instruction set changes based on what the user is asking.
* Diversity-aware – tracks over-used phrases and instructs the LLM to avoid them.
* Deterministic input – only data from the deterministic analysis is injected.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Persona definitions
# ---------------------------------------------------------------------------

_PERSONAS: dict[str, str] = {
    "junior_dev": (
        "You are a friendly senior engineer mentoring a junior developer. "
        "Use clear, jargon-free language, helpful analogies, and an encouraging tone. "
        "Explain 'why' before 'how'. Break things down step by step."
    ),
    "manager": (
        "You are a senior security consultant briefing a technical manager. "
        "Focus on business impact, risk quantification, resource implications, and ROI. "
        "Be concise and action-oriented. Avoid low-level implementation details unless asked."
    ),
    "security_expert": (
        "You are a peer security engineer in a technical discussion. "
        "Use precise technical language. Reference CWE IDs, NIST categories, and CVSS scoring "
        "where relevant. Discuss threat models, attack surfaces, and defence-in-depth strategies."
    ),
}

_DEFAULT_PERSONA = _PERSONAS["junior_dev"]


# ---------------------------------------------------------------------------
# Intent detection
# ---------------------------------------------------------------------------

_INTENT_PATTERNS: list[tuple[str, list[str]]] = [
    ("explain_issue",    [r"\bwhy\b", r"\breason\b", r"\bcause\b", r"\bwhat is\b", r"\bexplain\b"]),
    ("why_critical",     [r"\bcritical\b", r"\bsever\b", r"\bimportant\b", r"\bdangerous\b"]),
    ("how_to_fix",       [r"\bfix\b", r"\bsolv\b", r"\bremediat\b", r"\bhow\b", r"\bstep\b"]),
    ("compare_options",  [r"\bcompar\b", r"\bvs\b", r"\balternativ\b", r"\bdifferen\b"]),
    ("risk_explanation", [r"\brisk\b", r"\bscore\b", r"\bsimulat\b", r"\bmonte carlo\b", r"\bprobab\b"]),
    ("summary",          [r"\bsummar\b", r"\boverview\b", r"\boverall\b", r"\btotal\b"]),
]


def detect_intent(query: str) -> str:
    """Return an intent label based on keyword patterns in *query*."""
    lower = query.lower()
    for intent, patterns in _INTENT_PATTERNS:
        if any(re.search(p, lower) for p in patterns):
            return intent
    return "general_inquiry"


# ---------------------------------------------------------------------------
# Intent-specific instruction blocks
# ---------------------------------------------------------------------------

def _instruction_for_intent(intent: str, context: dict[str, Any]) -> str:
    risk_score   = context.get("risk_score", 0.0)
    risk_change  = context.get("risk_reduction", 0.0)
    total_issues = context.get("total_issues", 0)
    critical_n   = context.get("critical_count", 0)

    instructions: dict[str, str] = {
        "explain_issue": (
            "The user wants to understand a specific security issue.\n"
            "1. Reference SPECIFIC vulnerable code or configuration key if known.\n"
            "2. Explain WHY this exact pattern is risky – give a concrete attack scenario.\n"
            "3. Quantify potential impact (data breach, service downtime, credential theft…).\n"
            "4. Keep the response under 250 words."
        ),
        "why_critical": (
            f"The user wants to understand severity.\n"
            f"The overall risk score is {risk_score:.1f} / 100 "
            f"with {critical_n} critical issue(s) out of {total_issues} total.\n"
            "1. Paint a realistic threat scenario specific to their configuration.\n"
            "2. Map the risk score to a relatable business impact (e.g. data exposure, fines, downtime).\n"
            "3. Avoid just repeating 'it is critical' – show concrete consequences.\n"
            "4. Keep the response under 250 words."
        ),
        "how_to_fix": (
            "The user wants practical remediation steps.\n"
            "1. Lead with the single most impactful action.\n"
            "2. Provide a short, numbered fix procedure (max 5 steps).\n"
            "3. Mention any side-effects or things to watch out for.\n"
            "4. If a Blue Team fix was generated, refer to it concisely.\n"
            "5. Keep the response under 300 words."
        ),
        "compare_options": (
            "The user wants to compare two or more approaches.\n"
            "1. Present a brief pro/con table or numbered comparison.\n"
            "2. Recommend the most appropriate option for their context.\n"
            "3. Keep the response under 300 words."
        ),
        "risk_explanation": (
            f"The user wants to understand the Monte Carlo risk simulation results.\n"
            f"Risk before remediation: {risk_score:.1f} / 100.\n"
            f"Risk reduction after applying fixes: {risk_change:.1f}%.\n"
            "1. Explain what the risk score means in plain language.\n"
            "2. Describe what the probability distribution represents.\n"
            "3. Explain why the risk reduction percentage matters.\n"
            "4. Avoid heavy statistics jargon unless the user is a security expert.\n"
            "5. Keep the response under 300 words."
        ),
        "summary": (
            f"The user wants a high-level summary of the analysis.\n"
            f"Total issues: {total_issues}, Critical: {critical_n}, "
            f"Risk score: {risk_score:.1f}/100, Reduction: {risk_change:.1f}%.\n"
            "1. Lead with the headline risk status (good / concerning / critical).\n"
            "2. Name the top 2–3 most important issues.\n"
            "3. State the expected improvement after remediation.\n"
            "4. End with one clear recommended next action.\n"
            "5. Keep the response under 250 words."
        ),
        "general_inquiry": (
            "Answer the user's question using the analysis context provided. "
            "Be specific, helpful, and concise (under 300 words)."
        ),
    }
    return instructions.get(intent, instructions["general_inquiry"])


# ---------------------------------------------------------------------------
# Diversity constraint
# ---------------------------------------------------------------------------

def _diversity_constraint(avoid_phrases: list[str]) -> str:
    if not avoid_phrases:
        return ""
    phrases_str = ", ".join(f'"{p}"' for p in avoid_phrases)
    return (
        f"\nDIVERSITY REQUIREMENT: You have used the following phrases too "
        f"frequently in recent responses: {phrases_str}. "
        "Do NOT use any of these phrases. Express the same ideas differently."
    )


# ---------------------------------------------------------------------------
# Issue summary helper
# ---------------------------------------------------------------------------

def _summarise_issues(issues_summary: list[dict[str, Any]]) -> str:
    if not issues_summary:
        return "No issues detected."
    lines = []
    for i, issue in enumerate(issues_summary, 1):
        title    = issue.get("title", "Unknown")
        severity = issue.get("severity", "?").upper()
        rule_id  = issue.get("rule_id", "")
        line_no  = issue.get("line_number", "?")
        lines.append(f"  {i}. [{severity}] {title} ({rule_id}, line {line_no})")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class DynamicPromptBuilder:
    """
    Constructs system + user prompts for the LLM Explainer.

    Parameters
    ----------
    max_history_for_diversity:
        Number of past responses to consider when detecting over-used phrases.
    """

    def __init__(self, max_history_for_diversity: int = 5) -> None:
        self._max_history = max_history_for_diversity

    # ------------------------------------------------------------------
    def build(
        self,
        context: dict[str, Any],
        user_query: str,
        avoid_phrases: list[str] | None = None,
    ) -> dict[str, str]:
        """
        Assemble a ``{"system": ..., "user": ...}`` prompt dictionary.

        Parameters
        ----------
        context:
            Analysis context dict (produced by ``LLMExplainerService._build_context``).
        user_query:
            The raw question from the user.
        avoid_phrases:
            Phrases the LLM should not repeat (diversity enforcement).

        Returns
        -------
        dict[str, str]
            Ready-to-send prompt with ``"system"`` and ``"user"`` keys.
        """
        background    = context.get("user_background", "junior_dev")
        persona       = _PERSONAS.get(background, _DEFAULT_PERSONA)
        intent        = detect_intent(user_query)
        instruction   = _instruction_for_intent(intent, context)
        diversity     = _diversity_constraint(avoid_phrases or [])

        issues_text = _summarise_issues(context.get("issues_summary", []))

        system_prompt = (
            f"{persona}\n\n"
            f"TASK:\n{instruction}\n"
            f"{diversity}\n\n"
            "CRITICAL: Respond like a knowledgeable colleague, not a generated report. "
            "Use varied sentence structures. Reference specific details from the context below."
        )

        user_prompt = (
            f"Analysis context:\n"
            f"  File: {context.get('config_file', 'unknown')}\n"
            f"  Total issues: {context.get('total_issues', 0)}\n"
            f"  Critical: {context.get('critical_count', 0)}\n"
            f"  Risk score: {context.get('risk_score', 0.0):.1f} / 100\n"
            f"  Risk reduction after fixes: {context.get('risk_reduction', 0.0):.1f}%\n"
            f"\nTop issues:\n{issues_text}\n"
            f"\nUser question: {user_query}"
        )

        return {"system": system_prompt, "user": user_prompt}

    # ------------------------------------------------------------------
    def extract_overused_phrases(
        self, conversation_history: list[dict[str, str]]
    ) -> list[str]:
        """
        Scan recent responses and return phrases used more than twice.

        Parameters
        ----------
        conversation_history:
            List of ``{"query": ..., "response": ...}`` dicts.

        Returns
        -------
        list[str]
            Phrases to avoid in the next response.
        """
        recent = conversation_history[-self._max_history:]
        candidates = [
            "Based on the analysis",
            "根据分析结果",
            "I've analyzed",
            "经过检查",
            "As we can see",
            "It is important to note",
            "In conclusion",
            "To summarize",
        ]
        overused: list[str] = []
        for phrase in candidates:
            count = sum(1 for conv in recent if phrase.lower() in conv.get("response", "").lower())
            if count >= 2:
                overused.append(phrase)
        return overused
