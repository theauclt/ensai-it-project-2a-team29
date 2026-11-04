from dataclasses import dataclass
from typing import Literal, get_args


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


# Valeurs autorisées, pour ne journaliser que des valeurs de ces listes fermées
JUDGE_STATUSES = frozenset(get_args(JudgeStatus))
INJECTION_TYPES = frozenset(get_args(InjectionType))


@dataclass(frozen=True)
class InjectionVerdict:
    """Résultat de l'analyse d'injection par le juge LLM."""

    status: JudgeStatus
    injection_type: InjectionType | None = None
    explication: str | None = None
