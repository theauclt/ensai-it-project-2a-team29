import re

from ..service.interfaces.pii_detector import PIIDetector

from ..service.interfaces.pii_span import PIISpan


class RegexDetector(PIIDetector):
    """
    Détecte les PII à format fixe (NIR, IBAN, email, téléphone ...)
    par expressions régulières.
    """

    PATTERNS = {  # noqa: RUF012
        "EMAIL": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
        "TELEPHONE": 
        re.compile(r"(?<!\d)(?:(?:\+33|0033)\s?[1-9]|0[1-9])(?:[\s.\-]?\d{2}){4}(?!\d)"),
        "NIR": re.compile(r"\b[12]\d{12}\b")
    }

    async def detect(self, content: str) -> list[PIISpan]:
        spans: list[PIISpan] = []  # liste des résultats obtenus
        # on parcourt chaque type de PII connu
        for pii_type, pattern in self.PATTERNS.items():
            # finditer scanne tout le contenu d'un coup et renvoie
            # un match pour chaque occurrence trouvée, avec sa position.
            for match in pattern.finditer(content):
                # !!! à tester!!!
                spans.append(PIISpan(
                    text=match.group(),
                    type=pii_type,
                    start=match.start(),
                    end=match.end(),
                    source_detector="RegexDetector",
                ))
        return spans