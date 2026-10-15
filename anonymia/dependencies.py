"""
Composition root : seul module autorisé à nommer des classes concrètes
et à les assembler (cf. dossier d'analyse, section 2.1).
"""
import os

import httpx

from dotenv import load_dotenv
from .infrastructure.anonymization_strategy_factory import AnonymizationStrategyFactory
from .infrastructure.llm_detector import LLMDetector
from .infrastructure.regex_detector import RegexDetector
from .service.detection_service import DetectionService

# Charge automatiquement les variables du fichier .env dans os.environ
load_dotenv()

def build_llm_detector() -> LLMDetector:
    """
    Construit le détecteur LLM à partir des variables d'environnement :
      LLM_BASE_URL : ex. http://localhost:11434/v1 (Ollama) ou l'URL SSPCloud
      LLM_MODEL    : nom du modèle (ex. qwen2.5:3b)
      LLM_API_KEY  : clé API (inutile pour Ollama en local)
      LLM_TIMEOUT  : timeout en secondes (60 par défaut)
    """
    base_url = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
    model = os.environ.get("LLM_MODEL", "qwen2.5:3b")
    api_key = os.environ.get("LLM_API_KEY")
    timeout = float(os.environ.get("LLM_TIMEOUT", "60"))

    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout)
    return LLMDetector(client=client, model=model)


def build_detection_service(with_llm: bool = True) -> DetectionService:
    """Assemble le service. Mode dégradé = retirer le détecteur LLM de la liste."""
    detectors = [RegexDetector()]
    if with_llm:
        detectors.append(build_llm_detector())
    return DetectionService(
        detectors=detectors,
        strategy_factory=AnonymizationStrategyFactory(),
    )
