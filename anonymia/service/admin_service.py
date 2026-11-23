"""Gestion des comptes par les administrateurs (création, rôle, activation, suppression)."""
from .business_objects.user import User
from .interfaces.user_repository import UserRepository
from .mots_de_passe import MOT_DE_PASSE_MIN, hasher_mot_de_passe
from .surveillance_injections import SurveillanceInjections

ROLES = ("USER", "SUPERVISOR", "ADMIN")


class CompteIntrouvableError(Exception):
    """Aucun compte ne correspond à l'identifiant demandé."""


class LoginDejaPrisError(Exception):
    """Un compte porte déjà ce login."""


class DonneeInvalideError(ValueError):
    """Login, mot de passe ou rôle invalide."""


class OperationInterditeError(Exception):
    """Opération refusée pour protéger l'accès à l'application."""


class AdminService:
    """Gestion des comptes (F1), réservée aux administrateurs."""

    def __init__(self, user_repo: UserRepository, surveillance: SurveillanceInjections | None = None):
        """
        surveillance : renseigne, pour chaque compte, ses tentatives d'injection et s'il est
                       signalé (comportement dangereux). Sans elle, les compteurs restent à 0.
        """
        self._user_repo = user_repo
        self._surveillance = surveillance

    async def lister(self, requester: User) -> list[User]:
        """Tous les comptes, avec leurs tentatives d'injection."""
        self._verifier_admin(requester)
        return await self._annoter(await self._user_repo.find_all())

    async def creer(self, requester: User, login: str, mot_de_passe: str, role: str) -> User:
        """Crée un compte (login libre, mot de passe assez long, rôle connu)."""
        self._verifier_admin(requester)
        login = login.strip()
        role = self._valider_role(role)
        if not login or len(login) > 255:
            raise DonneeInvalideError("Login vide ou trop long (255 caractères maximum)")
        if len(mot_de_passe) < MOT_DE_PASSE_MIN:
            raise DonneeInvalideError(
                f"Mot de passe trop court ({MOT_DE_PASSE_MIN} caractères minimum)"
            )
        if await self._user_repo.find_by_login(login) is not None:
            raise LoginDejaPrisError("Ce login existe déjà")

        await self._user_repo.create(login, hasher_mot_de_passe(mot_de_passe), role)
        (cree,) = await self._annoter([await self._user_repo.find_by_login(login)])
        return cree

    async def changer_role(self, requester: User, user_id: int, role: str) -> User:
        """Change le rôle d'un compte ; on ne peut pas retirer le dernier ADMIN ni son propre rôle."""
        self._verifier_admin(requester)
        role = self._valider_role(role)
        cible = await self._trouver(user_id)

        if cible.role == "ADMIN" and role != "ADMIN":
            if cible.id == requester.id:
                raise OperationInterditeError(
                    "Un administrateur ne peut pas retirer son propre rôle"
                )
            await self._verifier_autre_admin(cible)

        await self._user_repo.update_role(user_id, role)
        return await self._trouver(user_id)

    async def definir_activation(self, requester: User, user_id: int, est_active: bool) -> User:
        """Active ou désactive un compte ; on ne peut pas désactiver le sien ni le dernier ADMIN."""
        self._verifier_admin(requester)
        cible = await self._trouver(user_id)

        if not est_active:
            if cible.id == requester.id:
                raise OperationInterditeError(
                    "Un administrateur ne peut pas désactiver son propre compte"
                )
            await self._verifier_autre_admin(cible)

        await self._user_repo.set_active(user_id, est_active)
        return await self._trouver(user_id)

    async def supprimer(self, requester: User, user_id: int) -> None:
        """Supprime un compte ; on ne peut pas supprimer le sien ni le dernier ADMIN."""
        self._verifier_admin(requester)
        cible = await self._trouver(user_id)

        if cible.id == requester.id:
            raise OperationInterditeError(
                "Un administrateur ne peut pas supprimer son propre compte"
            )
        await self._verifier_autre_admin(cible)

        await self._user_repo.delete(user_id)

    # ------------------------------------------------------------------

    @staticmethod
    def _verifier_admin(requester: User) -> None:
        """Refuse si le demandeur n'est pas ADMIN (le contrôle est ici, pas seulement dans la route)."""
        if requester.role != "ADMIN":
            raise PermissionError("La gestion des comptes est réservée aux administrateurs")

    @staticmethod
    def _valider_role(role: str) -> str:
        """Renvoie le rôle en majuscules, ou lève DonneeInvalideError s'il est inconnu."""
        role = role.strip().upper()
        if role not in ROLES:
            raise DonneeInvalideError(f"Rôle inconnu. Rôles possibles : {', '.join(ROLES)}")
        return role

    async def _trouver(self, user_id: int) -> User:
        """Le compte demandé, avec ses tentatives d'injection (CompteIntrouvableError s'il n'existe pas)."""
        user = await self._user_repo.find_by_id(user_id)
        if user is None:
            raise CompteIntrouvableError("Compte introuvable")
        (user,) = await self._annoter([user])
        return user

    async def _annoter(self, users: list[User]) -> list[User]:
        """Ajoute aux comptes leur nombre de tentatives d'injection et leur signalement."""
        if self._surveillance is None:
            return users
        return await self._surveillance.annoter(users)

    async def _verifier_autre_admin(self, cible: User) -> None:
        """Si la cible est un administrateur actif, un autre administrateur actif doit rester."""
        if cible.role != "ADMIN" or not cible.est_active:
            return
        autres = [
            u for u in await self._user_repo.find_all()
            if u.id != cible.id and u.role == "ADMIN" and u.est_active
        ]
        if not autres:
            raise OperationInterditeError("Il doit rester au moins un administrateur actif")