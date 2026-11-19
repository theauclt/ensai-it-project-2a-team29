"""
Limitation des tentatives de connexion (audit ER3-02) : blocage temporaire d'un login
qui cumule trop d'échecs, avec une horloge simulée pour ne jamais attendre.
"""
import logging

import pytest

from anonymia.service.limiteur_connexions import LimiteurConnexions, TropDeTentativesError


class Horloge:
    """Temps simulé : `avancer` remplace une vraie attente."""

    def __init__(self) -> None:
        self.maintenant = 1000.0

    def __call__(self) -> float:
        return self.maintenant

    def avancer(self, secondes: float) -> None:
        self.maintenant += secondes


@pytest.fixture
def horloge():
    return Horloge()


@pytest.fixture
def limiteur(horloge):
    # 3 échecs en 60 s bloquent le login pendant 120 s
    return LimiteurConnexions(max_echecs=3, fenetre=60, verrouillage=120, horloge=horloge)


def echouer(limiteur, login, fois):
    for _ in range(fois):
        limiteur.verifier(login)
        limiteur.enregistrer_echec(login)


def test_en_dessous_du_seuil_rien_n_est_bloque(limiteur):
    echouer(limiteur, "alice", 2)

    limiteur.verifier("alice")  # pas d'exception


def test_le_seuil_atteint_bloque_le_login(limiteur):
    echouer(limiteur, "alice", 3)

    with pytest.raises(TropDeTentativesError) as erreur:
        limiteur.verifier("alice")

    assert erreur.value.secondes == 120


def test_le_temps_restant_diminue_et_est_arrondi_au_dessus(limiteur, horloge):
    echouer(limiteur, "alice", 3)
    horloge.avancer(30.5)

    with pytest.raises(TropDeTentativesError) as erreur:
        limiteur.verifier("alice")

    assert erreur.value.secondes == 90  # 89,5 s restantes, jamais 0 tant que c'est bloqué


def test_le_blocage_prend_fin_et_le_compteur_repart_de_zero(limiteur, horloge):
    echouer(limiteur, "alice", 3)
    horloge.avancer(121)

    limiteur.verifier("alice")  # de nouveau autorisé
    echouer(limiteur, "alice", 2)
    limiteur.verifier("alice")  # 2 échecs seulement : pas de nouveau blocage


def test_les_vieux_echecs_ne_comptent_plus(limiteur, horloge):
    echouer(limiteur, "alice", 2)
    horloge.avancer(61)  # hors de la fenêtre de 60 s

    echouer(limiteur, "alice", 1)

    limiteur.verifier("alice")  # 1 seul échec récent


def test_une_connexion_reussie_remet_le_compteur_a_zero(limiteur):
    echouer(limiteur, "alice", 2)
    limiteur.enregistrer_succes("alice")

    echouer(limiteur, "alice", 2)

    limiteur.verifier("alice")


def test_les_logins_sont_independants(limiteur):
    echouer(limiteur, "alice", 3)

    limiteur.verifier("bob")  # le blocage d'alice ne touche pas bob


def test_un_login_inconnu_est_bloque_comme_un_login_existant(limiteur):
    # Le limiteur ne sait pas si le compte existe : il ne peut donc rien en révéler
    echouer(limiteur, "personne-n-a-ce-login", 3)

    with pytest.raises(TropDeTentativesError):
        limiteur.verifier("personne-n-a-ce-login")


def test_le_blocage_est_journalise_sans_mot_de_passe(limiteur, caplog):
    with caplog.at_level(logging.WARNING, logger="security"):
        echouer(limiteur, "alice", 3)

    assert any("bloquée" in m and "'alice'" in m for m in caplog.messages)


def test_un_login_geant_ne_remplit_pas_la_memoire(horloge):
    limiteur = LimiteurConnexions(max_echecs=1, verrouillage=120, horloge=horloge)
    login = "x" * 100_000

    limiteur.enregistrer_echec(login)

    with pytest.raises(TropDeTentativesError):
        limiteur.verifier(login)
    assert all(len(cle) <= 255 for cle in limiteur._bloques_jusqua)


def test_le_nombre_de_logins_suivis_est_borne(horloge):
    limiteur = LimiteurConnexions(max_echecs=3, horloge=horloge, max_logins=5)

    for i in range(50):  # 50 logins aléatoires, un échec chacun
        limiteur.enregistrer_echec(f"login-{i}")

    assert len(limiteur._echecs) <= 5


def test_un_seuil_invalide_est_refuse():
    with pytest.raises(ValueError):
        LimiteurConnexions(max_echecs=0)
