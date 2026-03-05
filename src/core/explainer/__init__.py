"""
src/core/explainer
~~~~~~~~~~~~~~~~~~
Optional LLM-based explanation layer.

By design this package is isolated from all security decision modules.
It receives only deterministic analysis outputs and returns natural language.

Public surface
--------------
from src.core.explainer import LLMExplainerService, DynamicPromptBuilder
"""

from src.core.explainer.llm_explainer import LLMExplainerService
from src.core.explainer.prompt_builder import DynamicPromptBuilder, detect_intent

__all__ = ["LLMExplainerService", "DynamicPromptBuilder", "detect_intent"]
