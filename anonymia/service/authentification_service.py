import bcrypt

from .business_objects.user import User
from .interfaces.user_repository import UserRepository


class AuthentificationService:
    """
    Service responsable de l'authentification des utilisateurs.

    Il utilise UserRepository pour récupérer l'utilisateur
    et vérifie ensuite son mot de passe.
    """

    MOT_DE_PASSE_MIN = 8

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

    async def creer_admin_initial(self, login: str, mot_de_passe: str) -> bool:
        """
        Crée le compte administrateur initial s'il n'existe pas encore.

        Appelée à chaque démarrage : si le login existe déjà, rien n'est
        modifié (le mot de passe éventuellement changé depuis est conservé).

        Returns:
            bool: True si le compte a été créé, False s'il existait déjà.
        """
        if len(mot_de_passe) < self.MOT_DE_PASSE_MIN:
            raise ValueError(
                f"ADMIN_PASSWORD trop court ({self.MOT_DE_PASSE_MIN} caractères minimum)"
            )
        if await self.__user_repository.find_by_login(login) is not None:
            return False

        password_hash = bcrypt.hashpw(
            mot_de_passe.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        await self.__user_repository.create(login, password_hash, "ADMIN")
        return True

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