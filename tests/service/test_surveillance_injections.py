"""Comptage des tentatives d'injection : signalement à 3, désactivation automatique à 10."""
import logging

import pytest

from anonymia.service.business_objects.user import User
from anonymia.service.surveillance_injections import (
    SEUIL_ALERTE,
    SEUIL_DESACTIVATION,
    CompteDesactiveError,
    SurveillanceInjections,
)
from tests.fakes import FakeTentativeInjectionRepository, FakeUserRepository

TYPES = ["ignore_instructions"]


@pytest.fixture
def users():
    return FakeUserRepository([
        User(1, "alice", "h", "USER"),
        User(2, "sup", "h", "SUPERVISOR"),
        User(3, "admin", "h", "ADMIN"),
    ])


@pytest.fixture
def tentatives():
    return FakeTentativeInjectionRepository()


@pytest.fixture
def surveillance(tentatives, users):
    return SurveillanceInjections(tentatives, users)


async def envoyer(surveillance, user_id, n, debut=0):
    """Envoie n documents suspects différents ; renvoie le dernier compteur."""
    nb = 0
    for i in range(debut, debut + n):
        nb = await surveillance.signaler(user_id, f"{i:064x}", TYPES)
    return nb


def test_seuils_par_defaut():
    assert (SEUIL_ALERTE, SEUIL_DESACTIVATION) == (3, 10)


@pytest.mark.parametrize(("alerte", "desactivation"), [(0, 10), (5, 4), (-1, -1)])
def test_seuils_incoherents_refuses(tentatives, users, alerte, desactivation):
    with pytest.raises(ValueError, match="Seuils"):
        SurveillanceInjections(tentatives, users, alerte, desactivation)


async def test_chaque_document_suspect_compte_une_fois(surveillance):
    assert await surveillance.signaler(1, "a" * 64, TYPES) == 1
    # le même document (bloqué, puis renvoyé avec confirmation) ne compte pas double
    assert await surveillance.signaler(1, "a" * 64, TYPES) == 1
    assert await surveillance.signaler(1, "b" * 64, TYPES) == 2


async def test_les_compteurs_sont_propres_a_chaque_compte(surveillance):
    await envoyer(surveillance, 1, 2)
    # même document envoyé par un autre compte : c'est une tentative de cet autre compte
    assert await surveillance.signaler(2, f"{0:064x}", TYPES) == 1


async def test_sous_le_seuil_d_alerte_le_compte_n_est_pas_signale(surveillance, users):
    await envoyer(surveillance, 1, SEUIL_ALERTE - 1)

    alice = (await surveillance.annoter(await users.find_all()))[0]

    assert (alice.tentatives_injection, alice.comportement_dangereux) == (2, False)


async def test_a_trois_tentatives_le_compte_est_signale_mais_reste_actif(surveillance, users):
    await envoyer(surveillance, 1, SEUIL_ALERTE)

    comptes = {u.login: u for u in await surveillance.annoter(await users.find_all())}

    assert comptes["alice"].comportement_dangereux is True
    assert comptes["alice"].tentatives_injection == 3
    assert comptes["alice"].est_active is True
    assert comptes["sup"].comportement_dangereux is False
    assert comptes["sup"].tentatives_injection == 0


async def test_a_dix_tentatives_le_compte_est_desactive(surveillance, users):
    assert await envoyer(surveillance, 1, SEUIL_DESACTIVATION - 1) == 9
    assert (await users.find_by_id(1)).est_active is True

    with pytest.raises(CompteDesactiveError, match="10 documents suspects") as erreur:
        await surveillance.signaler(1, "f" * 64, TYPES)

    assert erreur.value.nb_tentatives == 10
    assert (await users.find_by_id(1)).est_active is False


async def test_un_superviseur_est_desactive_comme_un_utilisateur(surveillance, users):
    with pytest.raises(CompteDesactiveError):
        await envoyer(surveillance, 2, SEUIL_DESACTIVATION)

    assert (await users.find_by_id(2)).est_active is False


async def test_un_administrateur_est_signale_mais_jamais_desactive(surveillance, users):
    assert await envoyer(surveillance, 3, 12) == 12

    admin = (await surveillance.annoter([await users.find_by_id(3)]))[0]
    assert admin.est_active is True
    assert admin.comportement_dangereux is True


async def test_apres_reactivation_une_nouvelle_tentative_redesactive(surveillance, users):
    with pytest.raises(CompteDesactiveError):
        await envoyer(surveillance, 1, SEUIL_DESACTIVATION)
    await users.set_active(1, True)  # un administrateur réactive le compte

    # le compteur n'est pas remis à zéro : la tentative suivante désactive de nouveau
    with pytest.raises(CompteDesactiveError, match="11 documents"):
        await surveillance.signaler(1, "e" * 64, TYPES)
    assert (await users.find_by_id(1)).est_active is False


async def test_seuils_configurables(tentatives, users):
    surveillance = SurveillanceInjections(tentatives, users, seuil_alerte=1, seuil_desactivation=2)

    await surveillance.signaler(1, "a" * 64, TYPES)
    assert (await surveillance.annoter([await users.find_by_id(1)]))[0].comportement_dangereux

    with pytest.raises(CompteDesactiveError):
        await surveillance.signaler(1, "b" * 64, TYPES)


async def test_un_compte_supprime_entre_temps_ne_fait_pas_d_erreur(surveillance, users):
    await users.delete(1)

    assert await envoyer(surveillance, 1, SEUIL_DESACTIVATION) == 10


async def test_le_journal_ne_contient_que_l_identifiant_et_le_compteur(surveillance, caplog):
    caplog.set_level(logging.WARNING, logger="security")

    with pytest.raises(CompteDesactiveError):
        await envoyer(surveillance, 1, SEUIL_DESACTIVATION)

    assert "Compte 1 désactivé automatiquement après 10 tentatives" in caplog.text
    assert "comportement dangereux" in caplog.text
    # ni empreinte de document, ni login
    assert f"{0:064x}" not in caplog.text
    assert "alice" not in caplog.text
