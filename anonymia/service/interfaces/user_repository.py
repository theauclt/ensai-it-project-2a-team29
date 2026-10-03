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
        pass