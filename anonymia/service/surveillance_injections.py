"""
Surveillance des tentatives d'injection de prompt, compte par compte.

Chaque envoi d'un document dans lequel le filtre d'injection repère des motifs suspects compte
comme une tentative pour le compte qui l'a envoyé, même si c'est le même document qu'avant.
Seule exception : un document bloqué puis renvoyé avec confirmation (« Caviarder quand même »)
est un seul envoi, il ne compte pas double.

- À partir de SEUIL_ALERTE tentatives, le compte est signalé aux administrateurs
  (« comportement dangereux » dans la liste des comptes).
- À partir de SEUIL_DESACTIVATION tentatives, le compte est désactivé automatiquement : il ne
  peut plus ni se connecter ni utiliser son jeton, jusqu'à ce qu'un administrateur le réactive.
  Le compteur n'est pas remis à zéro par la réactivation : une nouvelle tentative le désactive
  de nouveau.

Les comptes ADMIN sont signalés mais jamais désactivés automatiquement : cela pourrait bloquer
toute l'administration (un administrateur teste aussi le filtre avec des documents piégés).
"""
import logging
from datetime import UTC, datetime

from .business_objects.user import User
from .interfaces.tentative_injection_repository import TentativeInjectionRepository
from .interfaces.user_repository import UserRepository

# Même journal que les échecs de connexion : ce sont des événements de sécurité
logger = logging.getLogger("security")

SEUIL_ALERTE = 3
SEUIL_DESACTIVATION = 10


class CompteDesactiveError(Exception):
    """Le compte a atteint le seuil de désactivation : la requête en cours est refusée."""

    def __init__(self, nb_tentatives: int) -> None:
        """nb_tentatives : nombre de documents suspects envoyés par le compte."""
        super().__init__(
            f"Compte désactivé : {nb_tentatives} documents suspects d'injection de prompt "
            "ont été envoyés depuis ce compte. Contactez un administrateur pour le réactiver."
        )
        self.nb_tentatives = nb_tentatives


class SurveillanceInjections:
    """Compte les tentatives d'injection de chaque compte, le signale puis le désactive."""

    def __init__(
        self,
        tentatives_repo: TentativeInjectionRepository,
        user_repo: UserRepository,
        seuil_alerte: int = SEUIL_ALERTE,
        seuil_desactivation: int = SEUIL_DESACTIVATION,
    ) -> None:
        """
        seuil_alerte        : tentatives à partir desquelles le compte est signalé (3 par défaut).
        seuil_desactivation : tentatives à partir desquelles il est désactivé (10 par défaut).

        Raises:
            ValueError: si les seuils ne vérifient pas 1 <= seuil_alerte <= seuil_desactivation.
        """
        if not 1 <= seuil_alerte <= seuil_desactivation:
            raise ValueError(
                "Seuils d'injection invalides : il faut 1 <= seuil d'alerte <= seuil de désactivation"
            )
        self._tentatives_repo = tentatives_repo
        self._user_repo = user_repo
        self._seuil_alerte = seuil_alerte
        self._seuil_desactivation = seuil_desactivation

    async def signaler(
        self,
        user_id: int,
        hash_document: str,
        types_injection: list[str],
        en_attente_confirmation: bool = False,
        confirmation: bool = False,
    ) -> int:
        """
        Enregistre une tentative d'injection et applique les seuils.

        en_attente_confirmation : le document est bloqué jusqu'à confirmation (/caviarder sans
                                  confirmer) ; la tentative est comptée dès maintenant.
        confirmation            : le document est renvoyé avec confirmer=true. S'il suit un
                                  blocage du même document, il ne compte pas une seconde fois.

        On ne journalise que l'identifiant du compte et le nombre de tentatives, jamais le
        document.

        Returns:
            int: le nombre de tentatives du compte, celle-ci comprise.

        Raises:
            CompteDesactiveError: le compte (hors ADMIN) a atteint le seuil de désactivation ;
                il vient d'être désactivé s'il ne l'était pas déjà.
        """
        deja_comptee = confirmation and await self._tentatives_repo.confirmer(user_id, hash_document)
        if not deja_comptee:
            await self._tentatives_repo.enregistrer(
                user_id, hash_document, types_injection, datetime.now(UTC), en_attente_confirmation
            )
        nb = await self._tentatives_repo.compter(user_id)

        if nb >= self._seuil_alerte:
            logger.warning(
                "Compte %s : %d tentatives d'injection de prompt (comportement dangereux)", user_id, nb
            )
        if nb >= self._seuil_desactivation:
            user = await self._user_repo.find_by_id(user_id)
            if user is not None and user.role != "ADMIN":
                if user.est_active:
                    await self._user_repo.set_active(user_id, False)
                    logger.warning(
                        "Compte %s désactivé automatiquement après %d tentatives d'injection", user_id, nb
                    )
                raise CompteDesactiveError(nb)
        return nb

    async def annoter(self, users: list[User]) -> list[User]:
        """
        Renseigne, pour chaque compte, son nombre de tentatives et s'il est signalé comme
        ayant un comportement dangereux. Une seule requête pour toute la liste.
        """
        compteurs = await self._tentatives_repo.compter_par_utilisateur()
        for user in users:
            user.tentatives_injection = compteurs.get(user.id, 0)
            user.comportement_dangereux = user.tentatives_injection >= self._seuil_alerte
        return users
