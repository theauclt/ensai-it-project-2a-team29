#pip install spacy
#python -m spacy download fr_core_news_lg
# à ajouter dans dependencies

import asyncio
import threading

# threading sert à gérer les fils d'execution différemment de asyncio
from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.pii_detector import PIIDetector

MODELE_PAR_DEFAUT = "fr_core_news_lg"

# Étiquettes du modèle spaCy français -> types d'Anonymia (ceux que gèrent les stratégies).
# MISC (œuvres, événements, nationalités...) n'est pas une donnée personnelle : ignoré.
# NB : spaCy ne distingue pas nom et prénom, "Claire Martin" est donc renvoyé en un seul NOM.
TYPES = {"PER": "NOM", "LOC": "LIEU", "ORG": "ORGANISATION"}

# Composants inutiles à la seule reconnaissance d'entités : les exclure accélère le traitement
COMPOSANTS_INUTILES = ["parser", "lemmatizer", "morphologizer", "attribute_ruler"]


class SpacyModeleIntrouvableError(RuntimeError):
    """Le modèle spaCy n'est pas installé (ou spaCy lui-même est absent)."""


class SpacyDetector(PIIDetector):
    """
    Détecte les noms de personnes, lieux et organisations avec un modèle de NER
    (reconnaissance d'entités nommées) spaCy, exécuté en local : aucun service externe.

    Contrairement au LLM, le modèle ne « lit » pas de consignes : une injection de prompt
    dans le document n'a aucun effet sur lui.
    """

    def __init__(self, nlp):
        """
        nlp : pipeline spaCy déjà chargé (construit via charger(), ou un faux dans les tests).
        """
        self._nlp = nlp
        # Un pipeline spaCy n'est pas garanti thread-safe : une seule inférence à la fois
        self._verrou = threading.Lock()

    @classmethod
    def charger(cls, modele: str = MODELE_PAR_DEFAUT) -> "SpacyDetector":
        """Charge le modèle (plusieurs secondes et ~600 Mo en RAM pour fr_core_news_lg)."""
        # Import différé : spaCy n'est nécessaire que si ce détecteur est activé
        try:
            import spacy

            nlp = spacy.load(modele, exclude=COMPOSANTS_INUTILES)
        except (ImportError, OSError) as exc:
            raise SpacyModeleIntrouvableError(
                f"Modèle spaCy « {modele} » introuvable. Installation : "
                f"pip install spacy && python -m spacy download {modele}  "
                f"(ou désactiver ce détecteur avec NER_ENABLED=false)"
            ) from exc
        return cls(nlp)

    async def detect(self, content: str) -> list[PIISpan]:
        if not content.strip():
            return []

        # Calcul CPU synchrone : dans un thread, pour ne pas bloquer la boucle asyncio
        # (le détecteur LLM attend sa réponse réseau en même temps)
        doc = await asyncio.to_thread(self._analyser, content)

        spans: list[PIISpan] = []
        for entite in doc.ents:
            pii_type = TYPES.get(entite.label_)
            if pii_type is None or not entite.text.strip():
                continue
            spans.append(
                PIISpan(
                    text=entite.text,
                    type=pii_type,
                    start=entite.start_char,
                    end=entite.end_char,
                    source_detector="SpacyDetector",
                )
            )
        return spans

    def _analyser(self, content: str):
        with self._verrou:
            return self._nlp(content)