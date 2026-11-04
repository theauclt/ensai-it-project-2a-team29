from dataclasses import dataclass, field

from .injection_verdict import InjectionVerdict


@dataclass
class AnonymizationResult:
    document: str | None
    types_injection: list[str] = field(default_factory=list)
    confirmation_requise: bool = False
    # Détecteurs qui ont répondu (un détecteur en panne n'y figure pas : mode dégradé)
    detecteurs: list[str] = field(default_factory=list)
    # Verdict du juge LLM (FO3) ; None si aucun juge n'est configuré. Il informe, il ne bloque jamais.
    verdict_juge: InjectionVerdict | None = None