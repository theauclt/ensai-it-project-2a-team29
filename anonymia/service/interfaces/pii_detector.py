from abc import ABC, abstractmethod

from .pii_span import PIISpan


class PIIDetector(ABC):
    """
    Contrat commun à tous les détecteurs de PII.
    Une classe conforme doit savoir détecter les PII présentes
    dans un texte et renvoyer une liste de PIISpan.
    """

    @abstractmethod
    async def detect(self, content: str) -> list[PIISpan]:
        """Détecte les PII dans le texte et renvoie la liste des spans trouvés."""