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


def metadonnees_juge(verdict: InjectionVerdict | None) -> tuple[str | None, str | None]:
    """
    Ce qu'on peut enregistrer ou exposer d'un verdict : son statut et son type, jamais l'explication.

    Seules des valeurs de listes fermées sont gardées : une valeur inattendue ne peut pas faire
    entrer de texte libre (donc du contenu du document) dans l'historique ni dans l'API.
    Renvoie (None, None) s'il n'y a pas de verdict (pas de juge).
    """
    if verdict is None:
        return None, None
    statut = verdict.status if verdict.status in JUDGE_STATUSES else "unavailable"
    if statut != "detected":
        return statut, None
    return statut, verdict.injection_type if verdict.injection_type in INJECTION_TYPES else "other"

