"""
Limitation des tentatives de connexion (audit ER3-02).

Sans limite, un attaquant peut essayer autant de mots de passe qu'il veut sur un login. Ici, un
login qui cumule trop d'échecs dans une courte période est bloqué un moment : même le bon mot de
passe est alors refusé, ce qui rend la devinette beaucoup trop lente.

Choix de conception :
  - Les échecs sont comptés pour TOUT login, y compris ceux qui n'existent pas : le blocage ne
    révèle donc pas quels comptes existent (audit ER3-01).
  - Le blocage est temporaire. Un attaquant peut bloquer le compte d'une personne en échouant
    exprès, mais seulement pour la durée du blocage : c'est le prix de la protection.
  - Les compteurs sont gardés en mémoire du processus. Ils sont remis à zéro au redémarrage, et
    chaque processus a les siens : avec plusieurs processus, la limite est multipliée d'autant.
    Pour un déploiement réel, ils iraient dans un composant partagé (base, Redis, reverse proxy).
  - Le nombre de logins suivis est borné, pour qu'un attaquant ne puisse pas saturer la mémoire
    en envoyant des logins aléatoires.
"""
import logging
import math
import time
from collections import deque
from collections.abc import Callable

# Même journal que les alertes d'injection : ce sont des événements de sécurité
logger = logging.getLogger("security")

LONGUEUR_MAX_LOGIN = 255
MAX_LOGINS_SUIVIS = 10_000


class TropDeTentativesError(Exception):
    """Trop d'échecs de connexion : le login est bloqué pendant `secondes` secondes."""

    def __init__(self, secondes: int) -> None:
        """secondes : durée restante du blocage."""
        super().__init__(f"Trop de tentatives de connexion, réessayez dans {secondes} secondes")
        self.secondes = secondes


class LimiteurConnexions:
    """
    Compte les échecs de connexion par login et bloque temporairement ceux qui en cumulent trop.

    max_echecs   : nombre d'échecs qui déclenche le blocage
    fenetre      : durée (secondes) pendant laquelle les échecs comptent ensemble
    verrouillage : durée (secondes) du blocage
    horloge      : source de temps (remplacée dans les tests)
    """

    def __init__(
        self,
        max_echecs: int = 5,
        fenetre: float = 900.0,
        verrouillage: float = 900.0,
        horloge: Callable[[], float] = time.monotonic,
        max_logins: int = MAX_LOGINS_SUIVIS,
    ) -> None:
        """max_logins : nombre maximal de logins suivis en mémoire (voir les autres paramètres ci-dessus)."""
        if max_echecs < 1:
            raise ValueError("max_echecs doit valoir au moins 1")
        self._max_echecs = max_echecs
        self._fenetre = fenetre
        self._verrouillage = verrouillage
        self._horloge = horloge
        self._max_logins = max_logins
        self._echecs: dict[str, deque[float]] = {}
        self._bloques_jusqua: dict[str, float] = {}

    def verifier(self, login: str) -> None:
        """Lève TropDeTentativesError si le login est actuellement bloqué."""
        cle = self._cle(login)
        fin = self._bloques_jusqua.get(cle)
        if fin is None:
            return
        reste = fin - self._horloge()
        if reste > 0:
            raise TropDeTentativesError(math.ceil(reste))
        del self._bloques_jusqua[cle]  # le blocage est terminé : on repart de zéro

    def enregistrer_echec(self, login: str) -> None:
        """Note un échec ; bloque le login s'il atteint le nombre d'échecs autorisé."""
        cle = self._cle(login)
        maintenant = self._horloge()
        echecs = self._echecs.setdefault(cle, deque())
        self._oublier_les_vieux_echecs(echecs, maintenant)
        echecs.append(maintenant)

        if len(echecs) >= self._max_echecs:
            self._bloques_jusqua[cle] = maintenant + self._verrouillage
            del self._echecs[cle]
            logger.warning(
                "Connexion bloquée %d s pour le login %r après %d échecs",
                self._verrouillage,
                cle[:100],
                self._max_echecs,
            )
        self._borner_la_memoire(maintenant)

    def enregistrer_succes(self, login: str) -> None:
        """Une connexion réussie remet le compteur du login à zéro."""
        self._echecs.pop(self._cle(login), None)

    # ------------------------------------------------------------------

    @staticmethod
    def _cle(login: str) -> str:
        """Clé de suivi d'un login (tronquée pour borner la mémoire)."""
        return login[:LONGUEUR_MAX_LOGIN]

    def _oublier_les_vieux_echecs(self, echecs: deque[float], maintenant: float) -> None:
        """Retire les échecs plus vieux que la fenêtre de comptage."""
        while echecs and maintenant - echecs[0] > self._fenetre:
            echecs.popleft()

    def _borner_la_memoire(self, maintenant: float) -> None:
        """Garde au plus `max_logins` logins suivis : d'abord les périmés, puis les plus anciens."""
        if len(self._echecs) + len(self._bloques_jusqua) <= self._max_logins:
            return

        for cle in [c for c, fin in self._bloques_jusqua.items() if fin <= maintenant]:
            del self._bloques_jusqua[cle]
        for cle in [c for c, e in self._echecs.items() if not e or maintenant - e[-1] > self._fenetre]:
            del self._echecs[cle]

        while len(self._echecs) + len(self._bloques_jusqua) > self._max_logins and self._echecs:
            del self._echecs[next(iter(self._echecs))]  # le plus ancien en premier