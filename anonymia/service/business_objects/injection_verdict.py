from dataclasses import dataclass
from typing import Literal


InjectionType = Literal[
    "ignore_instructions",
    "role_manipulation",
    "prompt_extraction",
    "data_exfiltration",
    "other",
]

JudgeStatus = Literal[
    "detected",
    "not_detected",
    "unavailable",
]


@dataclass(frozen=True)
class InjectionVerdict:
    """Résultat de l'analyse d'injection par le juge LLM."""

    status: JudgeStatus
    injection_type: InjectionType | None = None
    explication: str | None = None
