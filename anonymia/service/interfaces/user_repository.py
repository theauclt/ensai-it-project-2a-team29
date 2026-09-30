from abc import ABC, abstractmethod

from business_object.user import User


class UserRepository(ABC):
    """
    Contrat commun à tous les détecteurs de PII.
    Une classe conforme doit savoir détecter les PII présentes
    dans un texte et renvoyer une liste de PIISpan.
    """
    @abstractmethod
    def find_by_login(self, login: str) -> User | None:
        """
        Recherche un utilisateur à partir de son login.

        Args:
            login (str): Le login de l'utilisateur recherché.

        Returns:
            User | None: L'utilisateur correspondant s'il existe,
            sinon None.
        """
        pass