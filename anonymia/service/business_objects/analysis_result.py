"""Résultat de l'analyse d'un document (PII repérées, sans caviardage)."""

from dataclasses import dataclass, field

from .injection_verdict import InjectionVerdict
from .pii_span import PIISpan


@dataclass
class AnalysisResult:
    """Résultat de DetectionService.analyse : les PII repérées, sans anonymisation."""

    spans: list[PIISpan] | None
    types_injection: list[str] = field(default_factory=list)
    confirmation_requise: bool = False
    # Détecteurs qui ont répondu (un détecteur en panne n'y figure pas : mode dégradé)
    detecteurs: list[str] = field(default_factory=list)
    # Verdict du juge LLM ; None si aucun juge n'est configuré
    verdict_juge: InjectionVerdict | None = None