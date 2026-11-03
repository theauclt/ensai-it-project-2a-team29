from abc import ABC, abstractmethod

from ..business_objects.user import User


class UserRepository(ABC):
    """
    Contrat commun aux implémentations de persistance des utilisateurs.
    Une classe conforme doit savoir rechercher un utilisateur à partir
    de son login.
    """
    @abstractmethod
    async def find_by_login(self, login: str) -> User | None:
        """
        Recherche un utilisateur à partir de son login.

        Args:
            login (str): Le login de l'utilisateur recherché.

        Returns:
            User | None: L'utilisateur correspondant s'il existe,
            sinon None.
        """

    @abstractmethod
    async def create(self, login: str, password_hash: str, role: str) -> None:
        """
        Enregistre un nouveau compte actif.

        Args:
            login (str): Le login du compte (unique).
            password_hash (str): L'empreinte du mot de passe (jamais le mot de passe).
            role (str): USER, SUPERVISOR ou ADMIN.
        """

    @abstractmethod
    async def find_by_id(self, user_id: int) -> User | None:
        """Recherche un utilisateur à partir de son identifiant (None s'il n'existe pas)."""

    @abstractmethod
    async def find_all(self) -> list[User]:
        """Renvoie tous les comptes, triés par identifiant."""

    @abstractmethod
    async def update_role(self, user_id: int, role: str) -> None:
        """Change le rôle d'un compte."""

    @abstractmethod
    async def set_active(self, user_id: int, est_active: bool) -> None:
        """Active ou désactive un compte."""

    @abstractmethod
    async def delete(self, user_id: int) -> None:
        """
        Supprime un compte. Ses traitements archivés sont supprimés avec lui
        (ON DELETE CASCADE en base).
        """
