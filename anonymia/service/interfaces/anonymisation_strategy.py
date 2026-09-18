from abc import ABC, abstractmethod

from .pii_span import PIISpan


class AnonymisationStrategy(ABC):
    """
    Contrat commun aux stratégies d'anonymisation.
    Une classe conforme transforme un document en y remplaçant
    les PII détectées, selon sa propre logique.
    """

    @abstractmethod
    def apply(self, content: str, spans: list[PIISpan]) -> str:
        """Caviarde le document"""