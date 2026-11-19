"""
Composition root : seul module autorisé à nommer des classes concrètes
et à les assembler (cf. dossier d'analyse, section 2.1).
"""
import os

import httpx
from dotenv import load_dotenv
from psycopg_pool import AsyncConnectionPool

from .infrastructure.anonymization_strategy_factory import AnonymizationStrategyFactory
from .infrastructure.llm_detector import LLMDetector
from .infrastructure.llm_injection_judge import LLMInjectionJudge
from .infrastructure.regex_detector import RegexDetector
from .infrastructure.spacy_detector import MODELE_PAR_DEFAUT, SpacyDetector
from .persistence.dao.db_connexion import construire_pool
from .persistence.postgres_archive_repository import PostgresArchiveRepository
from .persistence.postgres_tentative_injection_repository import (
    PostgresTentativeInjectionRepository,
)
from .persistence.postgres_user_repository import PostgresUserRepository
from .service.admin_service import AdminService
from .service.authentification_service import AuthentificationService
from .service.detection_service import DetectionService
from .service.history_service import HistoryService
from .service.interfaces.archive_repository import ArchiveRepository
from .service.interfaces.tentative_injection_repository import TentativeInjectionRepository
from .service.interfaces.user_repository import UserRepository
from .service.limiteur_connexions import LimiteurConnexions
from .service.prompt_injector_detector import PromptInjectionDetector
from .service.surveillance_injections import (
    SEUIL_ALERTE,
    SEUIL_DESACTIVATION,
    SurveillanceInjections,
)

# Charge automatiquement les variables du fichier .env dans os.environ
load_dotenv()


def build_llm_client() -> httpx.AsyncClient:
    """
    Construit le client HTTP du LLM à partir des variables d'environnement :
      LLM_BASE_URL : l'URL SSPCloud
      LLM_API_KEY  : clé API (inutile pour Ollama en local)
      LLM_TIMEOUT  : timeout en secondes (60 par défaut)
    Ce client est partagé entre le détecteur de PII et le juge d'injection.
    """
    base_url = os.environ.get("LLM_BASE_URL", "https://llm.lab.sspcloud.fr/api")
    api_key = os.environ.get("LLM_API_KEY")
    timeout = float(os.environ.get("LLM_TIMEOUT", "60"))

    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    return httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout)


def build_llm_detector(client: httpx.AsyncClient | None = None) -> LLMDetector:
    """
    Construit le détecteur LLM.
      LLM_MODEL : nom du modèle
    client : client HTTP à réutiliser (un nouveau est créé s'il est omis).
    """
    model = os.environ.get("LLM_MODEL", "qwen3-8-27b")
    return LLMDetector(client=client or build_llm_client(), model=model)


def build_injection_judge(client: httpx.AsyncClient) -> LLMInjectionJudge:
    """
    Construit le juge d'injection (FO3) sur le client HTTP partagé.
      LLM_JUDGE_MODEL : modèle du juge (par défaut, celui de LLM_MODEL)
    """
    model = os.environ.get("LLM_JUDGE_MODEL") or os.environ.get("LLM_MODEL", "qwen3-8-27b")
    return LLMInjectionJudge(client=client, model=model)


def build_spacy_detector() -> SpacyDetector:
    """
    Construit le détecteur NER local (spaCy). Variable d'environnement :
      SPACY_MODEL : nom du modèle installé (fr_core_news_lg par défaut)
    Lève SpacyModeleIntrouvableError si le modèle n'est pas installé.
    """
    return SpacyDetector.charger(os.environ.get("SPACY_MODEL", MODELE_PAR_DEFAUT))


def build_pool() -> AsyncConnectionPool:
    """
    Pool de connexions à PostgreSQL (variables POSTGRES_*), partagé par les deux dépôts.
    Il est créé fermé : main.py l'ouvre au démarrage (`await pool.open()`) et le ferme à l'arrêt.
    """
    return construire_pool()


def build_archive_repository(pool: AsyncConnectionPool) -> ArchiveRepository:
    """Dépôt de l'historique des traitements (PostgreSQL)."""
    return PostgresArchiveRepository(pool)


def build_user_repository(pool: AsyncConnectionPool) -> UserRepository:
    """Dépôt des comptes utilisateurs (PostgreSQL)."""
    return PostgresUserRepository(pool)


def build_tentative_injection_repository(pool: AsyncConnectionPool) -> TentativeInjectionRepository:
    """Dépôt des tentatives d'injection de prompt, par compte (PostgreSQL)."""
    return PostgresTentativeInjectionRepository(pool)


def build_surveillance_injections(
    tentatives_repo: TentativeInjectionRepository, user_repo: UserRepository
) -> SurveillanceInjections:
    """
    Signalement puis désactivation des comptes qui multiplient les injections. Variables :
      INJECTION_SEUIL_ALERTE        : tentatives à partir desquelles le compte est signalé (3 par défaut)
      INJECTION_SEUIL_DESACTIVATION : tentatives à partir desquelles il est désactivé (10 par défaut)
    """
    return SurveillanceInjections(
        tentatives_repo,
        user_repo,
        seuil_alerte=int(os.environ.get("INJECTION_SEUIL_ALERTE", str(SEUIL_ALERTE))),
        seuil_desactivation=int(
            os.environ.get("INJECTION_SEUIL_DESACTIVATION", str(SEUIL_DESACTIVATION))
        ),
    )


def build_detection_service(
    archive_repo: ArchiveRepository,
    with_llm: bool = True,
    with_ner: bool = False,
    surveillance: SurveillanceInjections | None = None,
) -> DetectionService:
    """
    Assemble le service. Mode dégradé = retirer le détecteur LLM de la liste.

    Le juge d'injection (FO3) n'existe que si le LLM est activé, et peut être désactivé avec
    LLM_JUDGE_ENABLED=false (il double les appels au LLM). Il partage le client HTTP du détecteur.
    surveillance : compte les tentatives d'injection de chaque compte (aucun comptage sans elle).
    """
    detectors = [RegexDetector()]
    judge = None
    if with_llm:
        client = build_llm_client()
        detectors.append(build_llm_detector(client))
        if os.environ.get("LLM_JUDGE_ENABLED", "true").lower() != "false":
            judge = build_injection_judge(client)
    if with_ner:
        detectors.append(build_spacy_detector())
    return DetectionService(
        detectors=detectors,
        strategy_factory=AnonymizationStrategyFactory(),
        archive_repo=archive_repo,
        injection_detector=PromptInjectionDetector(),
        injection_judge=judge,
        surveillance=surveillance,
    )


def build_history_service(
    archive_repo: ArchiveRepository, user_repo: UserRepository
) -> HistoryService:
    """Assemble le service de consultation de l'historique."""
    return HistoryService(archive_repo, user_repo)


def build_limiteur_connexions() -> LimiteurConnexions | None:
    """
    Limite les tentatives de connexion (audit ER3-02). Variables d'environnement :
      LOGIN_MAX_ECHECS          : échecs qui déclenchent le blocage (5 par défaut ; 0 = pas de limite)
      LOGIN_FENETRE_SECONDES    : durée pendant laquelle les échecs comptent ensemble (900 par défaut)
      LOGIN_VERROUILLAGE_SECONDES : durée du blocage (900 par défaut)
    """
    max_echecs = int(os.environ.get("LOGIN_MAX_ECHECS", "5"))
    if max_echecs <= 0:
        return None
    return LimiteurConnexions(
        max_echecs=max_echecs,
        fenetre=float(os.environ.get("LOGIN_FENETRE_SECONDES", "900")),
        verrouillage=float(os.environ.get("LOGIN_VERROUILLAGE_SECONDES", "900")),
    )


def build_auth_service(user_repo: UserRepository) -> AuthentificationService:
    """Assemble le service d'authentification (utilisé via Depends dans les routes)."""
    return AuthentificationService(user_repo, build_limiteur_connexions())


def build_admin_service(
    user_repo: UserRepository, surveillance: SurveillanceInjections | None = None
) -> AdminService:
    """Assemble le service de gestion des comptes (administrateurs)."""
    return AdminService(user_repo, surveillance)
