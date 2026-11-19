import asyncio
import bisect
import hashlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from .business_objects.analysis_result import AnalysisResult
from .business_objects.anonymization_result import AnonymizationResult
from .business_objects.audit_entry import AuditEntry
from .business_objects.injection_verdict import InjectionVerdict, metadonnees_juge
from .business_objects.pii_span import PIISpan
from .interfaces.archive_repository import ArchiveRepository
from .interfaces.injection_judge import InjectionJudge
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

# Valeur de strategie_anonymisation dans l'audit pour les analyses (sans anonymisation)
STRATEGIE_ANALYSE = "analyse"


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
        injection_judge: InjectionJudge | None = None,
    ):
        self._detectors = detectors
        self._strategy_factory = strategy_factory
        self._archive_repo = archive_repo
        self._injection_detector = injection_detector
        # Juge LLM facultatif (FO3) : sans juge, le service fonctionne comme avant
        self._injection_judge = injection_judge
    
    def available_strategies(self) -> list[str]:
        """Noms des stratégies d'anonymisation disponibles (endpoint /documents/strategies)."""
        return self._strategy_factory.available_strategies()

    async def aclose(self) -> None:
        """Ferme les ressources des détecteurs et du juge qui en ont (client HTTP du LLM)."""
        for collaborateur in (*self._detectors, self._injection_judge):
            close = getattr(collaborateur, "aclose", None)
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

    async def verifier_injection(
        self,
        content: str,
        user_id: int,
        en_attente_confirmation: bool = False,
        confirmation: bool = False,
    ) -> list[str]:
        """
        Passe le document au filtre d'injection, avant tout appel au LLM.

        Si le document est suspect, la tentative est comptée pour ce compte. Au seuil de
        désactivation, le compte est désactivé et CompteDesactiveError est levée : le document
        n'est pas traité.

        en_attente_confirmation : le document sera bloqué jusqu'à confirmation (/caviarder).
        confirmation            : le document est renvoyé avec confirmation ; s'il suit un
                                  blocage du même document, il ne compte pas une seconde fois.
        Pour /analyser (pas de confirmation), les deux restent à False.

        Returns:
            list[str]: les catégories d'injection repérées (vide si rien de suspect).
        """
        injection_types = self._injection_detector.detect(content)
        if injection_types and self._surveillance is not None:
            await self._surveillance.signaler(
                user_id,
                _empreinte(content),
                injection_types,
                en_attente_confirmation=en_attente_confirmation,
                confirmation=confirmation,
            )
        return injection_types

    async def detect(
        self,
        content: str,
        strategy_name: str,
        user_id: int,
        confirmed: bool = False,
    ) -> AnonymizationResult:
        strategy = self._strategy_factory.get_strategy(strategy_name)

        # Filtre d'injection avant les détecteurs (donc avant le LLM). Un compte qui atteint le
        # seuil de tentatives est désactivé ici (CompteDesactiveError) : rien n'est traité.
        injection_types = await self.verifier_injection(
            content, user_id, en_attente_confirmation=not confirmed, confirmation=confirmed
        )
        if injection_types and not confirmed:
            return AnonymizationResult(
                document=None,
                types_injection=injection_types,
                confirmation_requise=True,
            )

        anonymized = strategy.apply(content, spans)
        await self._archiver(
            content, user_id, strategy_name, spans, injection_types, detectors_ok, verdict_juge
        )
        return AnonymizationResult(
            document=anonymized,
            types_injection=injection_types,
            detecteurs=detectors_ok,
            verdict_juge=verdict_juge,
        )

    async def analyse(
        self, content: str, user_id: int, confirmed: bool = False
    ) -> AnalysisResult:
        """
        Repère les PII sans anonymiser (endpoint /documents/analyser).

        Même chemin que detect : filtre d'injection avant le LLM, juge, puis entrée d'audit
        (stratégie « analyse »). Aucun texte n'est envoyé au LLM sans trace.
        """
        spans, injection_types, detectors_ok, verdict_juge = await self._inspecter(
            content, confirmed
        )
        if spans is None:
            return AnalysisResult(
                spans=None, types_injection=injection_types, confirmation_requise=True
            )
        await self._archiver(
            content, user_id, STRATEGIE_ANALYSE, spans, injection_types, detectors_ok, verdict_juge
        )
        return AnalysisResult(
            spans=spans,
            types_injection=injection_types,
            detecteurs=detectors_ok,
            verdict_juge=verdict_juge,
        )

    async def _inspecter(
        self, content: str, confirmed: bool
    ) -> tuple[list[PIISpan] | None, list[str], list[str], InjectionVerdict | None]:
        """
        Étapes communes à detect et analyse : filtre d'injection, puis détection et juge.

        Renvoie (spans, types d'injection, détecteurs ayant répondu, verdict du juge).
        spans vaut None quand une confirmation est requise : rien n'a alors été envoyé
        au LLM.
        """
        # Filtre d'injection avant les détecteurs (donc avant le LLM)
        injection_types = self._injection_detector.detect(content)
        if injection_types and not confirmed:
            return None, injection_types, [], None

        # Le juge tourne en même temps que les détecteurs : on n'attend que le plus lent.
        # Ni _run_detectors ni _run_judge ne lèvent d'exception : une panne de l'un ne peut
        # donc ni bloquer la détection ni empêcher la suite.
        (spans, detectors_ok), verdict_juge = await asyncio.gather(
            self._run_detectors(content), self._run_judge(content)
        )
        return self._merge_spans(spans), injection_types, detectors_ok, verdict_juge

    async def _archiver(
        self,
        content: str,
        user_id: int,
        strategie: str,
        spans: list[PIISpan],
        injection_types: list[str],
        detectors_ok: list[str],
        verdict_juge: InjectionVerdict | None,
    ) -> None:
        """Enregistre l'entrée d'audit (métadonnées seulement, jamais le contenu)."""
        juge_statut, juge_type = metadonnees_juge(verdict_juge)
        await self._archive_repo.save(
            AuditEntry(
                user_id=user_id,
                date_traitement=datetime.now(UTC),
                hash_document=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                strategie_anonymisation=strategie,
                detecteurs_contributeurs=",".join(detectors_ok),
                nb_pii_detectees=len(spans),
                injection_suspectee=bool(injection_types),
                types_pii=vers_texte(compter(spans)),
                juge_statut=juge_statut,
                juge_type=juge_type,
            )
        )

    async def _run_judge(self, content: str) -> InjectionVerdict | None:
        """
        Demande son verdict au juge d'injection (None s'il n'y a pas de juge).

        Toute erreur du juge devient un verdict « unavailable » : le traitement continue.
        On ne logge que le type d'erreur, jamais le contenu du document.
        """
        if self._injection_judge is None:
            return None
        try:
            return await self._injection_judge.analyze(content)
        except Exception as exc:  # noqa: BLE001 - le juge ne doit jamais bloquer le pipeline
            logger.warning("Juge d'injection indisponible : %s", type(exc).__name__)
            return InjectionVerdict(status="unavailable")

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