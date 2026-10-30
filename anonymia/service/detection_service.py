import asyncio
import hashlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from .business_objects.audit_entry import AuditEntry
from .business_objects.pii_span import PIISpan
from .interfaces.archive_repository import ArchiveRepository
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
    Orchestre la détection des PII par tous les détecteurs, l'anonymisation
    du document selon la stratégie choisie, et l'archivage du traitement.
    """

    def __init__(
        self,
        detectors: list[PIIDetector],
        strategy_factory: "AnonymizationStrategyFactory",
        archive_repo: ArchiveRepository,
    ):
        # Collaborateurs injectés : le service ne crée jamais RegexDetector() lui-même
        self._detectors = detectors
        self._strategy_factory = strategy_factory
        self._archive_repo = archive_repo

    async def analyze(self, content: str) -> list[PIISpan]:
        """Renvoie la liste fusionnée des PII détectées (endpoint /documents/analyser)."""
        spans, _ = await self._run_detectors(content)
        return self._merge_spans(spans)

    async def detect(self, content: str, strategy_name: str, user_id: int) -> str:
        """
        Renvoie le document anonymisé et archive les métadonnées du traitement
        (endpoint /documents/caviarder).
        """
        # Stratégie vérifiée en premier : un nom inconnu échoue tout de suite,
        # sans attendre l'appel au LLM (~5 s)
        strategy = self._strategy_factory.get_strategy(strategy_name)

        spans, detectors_ok = await self._run_detectors(content)
        spans = self._merge_spans(spans)
        anonymized = strategy.apply(content, spans)

        # Uniquement des métadonnées : ni le contenu, ni les PII elles-mêmes.
        # Si l'archivage échoue, l'erreur remonte : pas de traitement sans trace (F4).
        await self._archive_repo.save(
            AuditEntry(
                user_id=user_id,
                date_traitement=datetime.now(UTC),
                hash_document=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                strategie_anonymisation=strategy_name,
                detecteurs_contributeurs=",".join(detectors_ok),
                nb_pii_detectees=len(spans),
            )
        )
        return anonymized

    async def _run_detectors(self, content: str) -> tuple[list[PIISpan], list[str]]:
        """
        Lance tous les détecteurs en parallèle.

        Renvoie les spans trouvés et les noms des détecteurs qui ont répondu
        (un détecteur en panne n'y figure pas : le mode dégradé reste visible
        dans l'historique).
        """
        # gather lance les détecteurs en même temps : on attend seulement le plus lent
        # return_exceptions=True : une panne ne fait pas échouer les autres
        results = await asyncio.gather(
            *(detector.detect(content) for detector in self._detectors),
            return_exceptions=True,
        )

        spans: list[PIISpan] = []
        detectors_ok: list[str] = []
        for detector, result in zip(self._detectors, results, strict=True):
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
            detectors_ok.append(type(detector).__name__)
        return spans, detectors_ok

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