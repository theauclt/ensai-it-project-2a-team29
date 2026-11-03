from .business_objects.user import User
from .interfaces.user_repository import UserRepository
from .mots_de_passe import MOT_DE_PASSE_MIN, hasher_mot_de_passe

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

    def __init__(self, user_repo: UserRepository):
        self._user_repo = user_repo

    async def lister(self, requester: User) -> list[User]:
        self._verifier_admin(requester)
        return await self._user_repo.find_all()

    async def creer(self, requester: User, login: str, mot_de_passe: str, role: str) -> User:
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
        return await self._user_repo.find_by_login(login)

    async def changer_role(self, requester: User, user_id: int, role: str) -> User:
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
        # Défense en profondeur : le contrôle est ici, pas seulement dans la route
        if requester.role != "ADMIN":
            raise PermissionError("La gestion des comptes est réservée aux administrateurs")

    @staticmethod
    def _valider_role(role: str) -> str:
        role = role.strip().upper()
        if role not in ROLES:
            raise DonneeInvalideError(f"Rôle inconnu. Rôles possibles : {', '.join(ROLES)}")
        return role

    async def _trouver(self, user_id: int) -> User:
        user = await self._user_repo.find_by_id(user_id)
        if user is None:
            raise CompteIntrouvableError("Compte introuvable")
        return user

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
