import logging
import re
from datetime import datetime, timezone


class PromptInjectionDetector:
    """
    Détecte des motifs pouvant indiquer une tentative
    de prompt injection dans un document.
    """

    PATTERNS = {  # noqa: RUF012
        "instruction_override": [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"disregard\s+(all\s+)?instructions",
            r"ignore\s+the\s+system\s+prompt",
            r"oublie\s+(toutes\s+)?les\s+instructions",
        ],
        "role_manipulation": [
            r"you\s+are\s+now\s+",
            r"act\s+as\s+an\s+unrestricted",
            r"pretend\s+to\s+be\s+",
            r"tu\s+es\s+maintenant\s+",
        ],
        "prompt_extraction": [
            r"reveal\s+(your\s+)?system\s+prompt",
            r"show\s+(me\s+)?your\s+instructions",
            r"affiche\s+(ton\s+)?prompt\s+système",
        ],
        "data_exfiltration": [
            r"send\s+(all\s+)?confidential\s+information",
            r"exfiltrate\s+",
            r"transmets\s+(toutes\s+)?les\s+informations\s+confidentielles",
        ]
    }

    def __init__(self):
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)

    def detect(self, document_text):
        """
        Analyse le texte et retourne les catégories suspectes.
        Ne conserve pas le contenu du document.
        """

        detected_types = []

        normalized_text = document_text.lower()

        for category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, normalized_text):
                    detected_types.append(category)
                    break

        if detected_types:
            self._log_events(detected_types)

        return detected_types

    def _log_events(self, detected_types):
        """
        Journalise uniquement le type et la date.
        """

        timestamp = datetime.now(timezone.utc).isoformat()

        for event_type in detected_types:
            self.logger.warning(
                "Suspicious content detected | type=%s | date=%s",
                event_type,
                timestamp
            )

    def analyze(self, document_text):
        """
        Point d'entrée principal du filtre.
        Retourne le résultat de l'analyse sans bloquer
        le traitement du document.
        """

        detected_types = self.detect(document_text)

        return {
            "suspicious_content": bool(detected_types),
            "detected_types": detected_types,
            "warning": bool(detected_types)
        }
