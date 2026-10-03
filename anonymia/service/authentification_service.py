import bcrypt

from ..business_objects.user import User
from ..interfaces.user_repository import UserRepository


class AuthentificationService:
    """
    Service responsable de l'authentification des utilisateurs.

    Il utilise UserRepository pour récupérer l'utilisateur
    et vérifie ensuite son mot de passe.
    """

    def __init__(self, user_repository: UserRepository) -> None:
        self.__user_repository = user_repository

    async def authentifier(
        self,
        login: str,
        mot_de_passe: str,
    ) -> User | None:
        """
        Authentifie un utilisateur à partir de son login
        et de son mot de passe.

        Returns:
            User | None: l'utilisateur si l'authentification réussit,
            sinon None.
        """

        user = await self.__user_repository.find_by_login(login)

        if user is None:
            return None

        if not user.est_active:
            return None

        if not self.__verifier_mot_de_passe(
            mot_de_passe,
            user.password_hash,
        ):
            return None

        return user

    @staticmethod
    def __verifier_mot_de_passe(
        mot_de_passe: str,
        password_hash: str,
    ) -> bool:
        """
        Vérifie qu'un mot de passe correspond à son hash.
        """

        return bcrypt.checkpw(
            mot_de_passe.encode("utf-8"),
            password_hash.encode("utf-8"),
        )

        # bcrypt est un algorithme de hachage adapté aux mots de passe.
        # Lors du hachage, il génère automatiquement un salt aléatoire,
        # qui est intégré au hash stocké en base de données.
        # Lors de la connexion, checkpw() utilise ce salt pour vérifier
        # le mot de passe saisi sans jamais stocker le mot de passe en clair.
        # penser à le mettre dans le requirement.txt