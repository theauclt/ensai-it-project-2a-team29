from abc import ABC, abstractmethod
from datetime import datetime


class TentativeInjectionRepository(ABC):
    """
    Contrat de persistance des tentatives d'injection de prompt, par utilisateur.

    Une tentative est un document dans lequel le filtre d'injection a repéré des motifs
    suspects. Seule l'empreinte du document est conservée, jamais son contenu. Un même
    document envoyé plusieurs fois par le même compte (par exemple bloqué, puis renvoyé avec
    confirmation) ne compte qu'une fois.
    """

    @abstractmethod
    async def enregistrer(
        self,
        user_id: int,
        hash_document: str,
        types_injection: list[str],
        date_tentative: datetime,
    ) -> None:
        """
        Enregistre une tentative. Sans effet si ce compte a déjà envoyé ce document.

        Args:
            user_id (int): Le compte qui a envoyé le document.
            hash_document (str): L'empreinte SHA-256 du document (jamais le document).
            types_injection (list[str]): Les catégories repérées par le filtre.
            date_tentative (datetime): La date de la tentative (UTC).
        """

    @abstractmethod
    async def compter(self, user_id: int) -> int:
        """Nombre de documents suspects distincts envoyés par ce compte."""

    @abstractmethod
    async def compter_par_utilisateur(self) -> dict[int, int]:
        """Nombre de tentatives de chaque compte (les comptes sans tentative sont absents)."""
