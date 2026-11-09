import bcrypt

from .business_objects.user import User
from .interfaces.user_repository import UserRepository
from .mots_de_passe import MOT_DE_PASSE_MIN, hasher_mot_de_passe

# bcrypt ne lit que les 72 premiers octets d'un mot de passe et (version 5) refuse les plus longs
MOT_DE_PASSE_MAX_OCTETS = 72

# Empreinte d'un mot de passe quelconque, calculée une fois. Elle sert à faire le même travail
# (un calcul bcrypt) quand le login n'existe pas : le temps de réponse ne révèle plus quels
# comptes existent.
_EMPREINTE_FACTICE = bcrypt.hashpw(b"empreinte-factice", bcrypt.gensalt()).decode("utf-8")


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

        Le calcul bcrypt est fait dans tous les cas (login inconnu, compte désactivé, mot de
        passe trop long) et la réponse est la même : rien ne distingue ces échecs.

        Returns:
            User | None: l'utilisateur si l'authentification réussit,
            sinon None.
        """

        user = await self.__user_repository.find_by_login(login)

        empreinte = user.password_hash if user is not None else _EMPREINTE_FACTICE
        mot_de_passe_valide = self.__verifier_mot_de_passe(mot_de_passe, empreinte)

        if user is None or not user.est_active or not mot_de_passe_valide:
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
        if len(mot_de_passe) < MOT_DE_PASSE_MIN:
            raise ValueError(
                f"ADMIN_PASSWORD trop court ({MOT_DE_PASSE_MIN} caractères minimum)"
            )
        if len(mot_de_passe.encode("utf-8")) > MOT_DE_PASSE_MAX_OCTETS:
            raise ValueError(
                f"ADMIN_PASSWORD trop long ({MOT_DE_PASSE_MAX_OCTETS} octets maximum)"
            )
        if await self.__user_repository.find_by_login(login) is not None:
            return False

        await self.__user_repository.create(
            login, hasher_mot_de_passe(mot_de_passe), "ADMIN"
        )
        return True

    @staticmethod
    def __verifier_mot_de_passe(
        mot_de_passe: str,
        password_hash: str,
    ) -> bool:
        """
        Vérifie qu'un mot de passe correspond à son hash.

        bcrypt est un algorithme de hachage adapté aux mots de passe. Lors du hachage, il
        génère automatiquement un sel aléatoire, intégré au hash stocké en base. Lors de la
        connexion, checkpw() utilise ce sel pour vérifier le mot de passe saisi.

        Une entrée que bcrypt refuse (mot de passe de plus de 72 octets, empreinte mal formée)
        est un simple échec, jamais une erreur serveur.
        """
        try:
            return bcrypt.checkpw(
                mot_de_passe.encode("utf-8"),
                password_hash.encode("utf-8"),
            )
        except ValueError:
            return False