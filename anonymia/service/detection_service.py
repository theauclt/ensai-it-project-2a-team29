import asyncio
import logging
from typing import TYPE_CHECKING

from .business_objects.pii_span import PIISpan
from .interfaces.pii_detector import PIIDetector

# Import utilisé uniquement pour le typage : pas de dépendance à l'exécution
# de service/ vers infrastructure/
if TYPE_CHECKING:
    from ..infrastructure.anonymization_strategy_factory import (
        AnonymizationStrategyFactory,
    )

logger = logging.getLogger(__name__)


class DetectionService:
    """
    Orchestre la détection des PII par tous les détecteurs, puis
    l'anonymisation du document selon la stratégie choisie.
    """

    def __init__(
        self,
        detectors: list[PIIDetector],
        strategy_factory: "AnonymizationStrategyFactory",
    ):
        # Collaborateurs injectés : le service ne crée jamais RegexDetector() lui-même
        self._detectors = detectors
        self._strategy_factory = strategy_factory

    async def detect(self, content: str, strategy_name: str) -> str:
        """Renvoie le document anonymisé selon la stratégie demandée."""
        spans = await self._run_detectors(content)
        spans = self._merge_spans(spans)
        strategy = self._strategy_factory.get_strategy(strategy_name)
        return strategy.apply(content, spans)

    async def _run_detectors(self, content: str) -> list[PIISpan]:
        """Lance tous les détecteurs en parallèle et regroupe leurs résultats."""
        # gather lance les détecteurs en même temps : on attend seulement le plus lent
        # return_exceptions=True : une panne ne fait pas échouer les autres
        results = await asyncio.gather(  # noqa: F821
            *(detector.detect(content) for detector in self._detectors),
            return_exceptions=True,
        )

        spans: list[PIISpan] = []
        for detector, result in zip(self._detectors, results):
            if isinstance(result, Exception):
                # Mode dégradé : on ignore ce détecteur et on continue avec les autres.
                # On ne logge que le type d'erreur, jamais le contenu du document.
                logger.warning(
                    "Détecteur %s indisponible : %s",
                    type(detector).__name__,
                    type(result).__name__,
                )
                continue
            spans.extend(result)
        return spans

    @staticmethod
    def _merge_spans(spans: list[PIISpan]) -> list[PIISpan]:
        """
        Supprime les chevauchements entre spans.

        Règle : on garde le span qui commence en premier, et à début égal
        le plus long. Les spans qui empiètent sur un span déjà gardé sont écartés.
        """
        merged: list[PIISpan] = []
        last_end = 0  # fin du dernier span gardé

        # tri par début croissant, puis par longueur décroissante
        for span in sorted(spans, key=lambda s: (s.start, -(s.end - s.start))):
            if span.start >= last_end:  # aucun chevauchement avec le dernier gardé
                merged.append(span)
                last_end = span.end
        return merged