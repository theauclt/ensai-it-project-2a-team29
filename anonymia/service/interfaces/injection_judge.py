from abc import ABC, abstractmethod

from ..business_objects.injection_verdict import InjectionVerdict


class InjectionJudge(ABC):
    """
    Contrat du juge d'injection (FO3).

    Une classe conforme sait dire si un document tente de manipuler le système et renvoie
    un InjectionVerdict. Son verdict informe : il ne bloque jamais le traitement.
    """

    @abstractmethod
    async def analyze(self, content: str) -> InjectionVerdict:
        """Analyse le document et renvoie le verdict du juge."""
