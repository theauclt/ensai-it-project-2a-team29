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
