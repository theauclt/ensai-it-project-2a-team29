"""Contrat de persistance des tentatives d'injection."""

from abc import ABC, abstractmethod
from datetime import datetime


class TentativeInjectionRepository(ABC):
    """
    Contrat de persistance des tentatives d'injection de prompt, par utilisateur.

    Une tentative est un envoi de document dans lequel le filtre d'injection a repéré des
    motifs suspects. Chaque envoi compte, même si c'est le même document. Seule exception :
    un document bloqué en attente de confirmation, puis renvoyé avec confirmation, est un seul
    envoi (la confirmation « consomme » la tentative en attente). Seule l'empreinte du document
    est conservée, jamais son contenu.
    """

    @abstractmethod
    async def enregistrer(
        self,
        user_id: int,
        hash_document: str,
        types_injection: list[str],
        date_tentative: datetime,
        en_attente_confirmation: bool = False,
    ) -> None:
        """
        Enregistre une nouvelle tentative.

        Args:
            user_id (int): Le compte qui a envoyé le document.
            hash_document (str): L'empreinte SHA-256 du document (jamais le document).
            types_injection (list[str]): Les catégories repérées par le filtre.
            date_tentative (datetime): La date de la tentative (UTC).
            en_attente_confirmation (bool): Le document a été bloqué et attend une confirmation.
        """

    @abstractmethod
    async def confirmer(self, user_id: int, hash_document: str) -> bool:
        """
        Marque comme confirmée la dernière tentative en attente de ce compte pour ce document.

        Returns:
            bool: True si une tentative en attente existait (la confirmation n'est donc pas une
            nouvelle tentative), False sinon.
        """

    @abstractmethod
    async def compter(self, user_id: int) -> int:
        """Nombre de tentatives de ce compte."""

    @abstractmethod
    async def compter_par_utilisateur(self) -> dict[int, int]:
        """Nombre de tentatives de chaque compte (les comptes sans tentative sont absents)."""