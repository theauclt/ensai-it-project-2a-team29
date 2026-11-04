import asyncio
import bisect
import hashlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from .business_objects.anonymization_result import AnonymizationResult
from .business_objects.audit_entry import AuditEntry
from .business_objects.pii_span import PIISpan
from .interfaces.archive_repository import ArchiveRepository
from .interfaces.pii_detector import PIIDetector
from .prompt_injector_detector import PromptInjectionDetector
from .types_pii import compter, vers_texte

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
        injection_detector: PromptInjectionDetector,
    ):
        self._detectors = detectors
        self._strategy_factory = strategy_factory
        self._archive_repo = archive_repo
        self._injection_detector = injection_detector
    
    def available_strategies(self) -> list[str]:
        """Noms des stratégies d'anonymisation disponibles (endpoint /documents/strategies)."""
        return self._strategy_factory.available_strategies()

    async def aclose(self) -> None:
        """Ferme les ressources des détecteurs qui en ont (client HTTP du LLM)."""
        for detector in self._detectors:
            close = getattr(detector, "aclose", None)
            if close is not None:
                await close()

    async def analyze(self, content: str) -> list[PIISpan]:
        """Renvoie la liste fusionnée des PII détectées (endpoint /documents/analyser)."""
        spans, _ = await self.analyze_with_status(content)
        return spans

    async def analyze_with_status(self, content: str) -> tuple[list[PIISpan], list[str]]:
        """Comme analyze, avec en plus les noms des détecteurs qui ont répondu."""
        spans, detectors_ok = await self._run_detectors(content)
        return self._merge_spans(spans), detectors_ok

    def injection_types(self, content: str) -> list[str]:
        """Catégories d'injection de prompt repérées dans le texte (vide si rien de suspect)."""
        return self._injection_detector.detect(content)

    async def detect(
        self,
        content: str,
        strategy_name: str,
        user_id: int,
        confirmed: bool = False,
    ) -> AnonymizationResult:
        strategy = self._strategy_factory.get_strategy(strategy_name)

        # Filtre d'injection avant les détecteurs (donc avant le LLM)
        injection_types = self._injection_detector.detect(content)
        if injection_types and not confirmed:
            return AnonymizationResult(
                document=None,
                types_injection=injection_types,
                confirmation_requise=True,
            )

        spans, detectors_ok = await self._run_detectors(content)
        spans = self._merge_spans(spans)
        anonymized = strategy.apply(content, spans)

        await self._archive_repo.save(
            AuditEntry(
                user_id=user_id,
                date_traitement=datetime.now(UTC),
                hash_document=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                strategie_anonymisation=strategy_name,
                detecteurs_contributeurs=",".join(detectors_ok),
                nb_pii_detectees=len(spans),
                injection_suspectee=bool(injection_types),
                types_pii=vers_texte(compter(spans)),
            )
        )
        return AnonymizationResult(document=anonymized, types_injection=injection_types, detecteurs=detectors_ok)

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

        Règle : on garde d'abord les spans de plus forte confiance ; à confiance égale,
        celui qui commence en premier, et à début égal le plus long. Un span qui empiète
        sur un span déjà gardé est écarté. Le résultat est trié par position.

        La confiance sert seulement à départager deux détections incompatibles : aucune
        PII n'est écartée parce que sa confiance est basse.
        """
        kept: list[PIISpan] = []
        starts: list[int] = []  # débuts des spans gardés, triés (kept reste trié comme starts)

        for span in sorted(spans, key=lambda s: (-s.confidence, s.start, -(s.end - s.start))):
            i = bisect.bisect_left(starts, span.start)
            # les spans gardés ne se chevauchent pas : seuls les voisins immédiats comptent
            if i > 0 and kept[i - 1].end > span.start:
                continue
            if i < len(kept) and kept[i].start < span.end:
                continue
            kept.insert(i, span)
            starts.insert(i, span.start)
        return kept
