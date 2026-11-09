"""
Authentification : aucun échec ne doit se distinguer d'un autre (audit ER3-01).
Même travail (un calcul bcrypt) et même réponse pour un login inconnu, un compte désactivé,
un mauvais mot de passe, un mot de passe de plus de 72 octets ou une empreinte invalide.
"""
import bcrypt
import pytest

from anonymia.service import authentification_service as module
from anonymia.service.authentification_service import (
    MOT_DE_PASSE_MAX_OCTETS,
    AuthentificationService,
)
from anonymia.service.business_objects.user import User
from anonymia.service.mots_de_passe import hasher_mot_de_passe
from tests.fakes import FakeUserRepository


def make_user(mot_de_passe="motdepasse123", est_active=True, password_hash=None):
    return User(
        id=1,
        login="alice",
        password_hash=password_hash or hasher_mot_de_passe(mot_de_passe),
        role="USER",
        est_active=est_active,
    )


@pytest.fixture
def appels_bcrypt(monkeypatch):
    """Compte les appels à bcrypt.checkpw faits par le service."""
    appels = []
    vrai_checkpw = bcrypt.checkpw

    def espion(mot_de_passe, empreinte):
        appels.append(empreinte)
        return vrai_checkpw(mot_de_passe, empreinte)

    monkeypatch.setattr(module.bcrypt, "checkpw", espion)
    return appels


async def test_connexion_reussie():
    service = AuthentificationService(FakeUserRepository([make_user()]))

    assert (await service.authentifier("alice", "motdepasse123")).login == "alice"


async def test_un_login_inconnu_fait_quand_meme_un_calcul_bcrypt(appels_bcrypt):
    service = AuthentificationService(FakeUserRepository())

    assert await service.authentifier("inconnu", "motdepasse123") is None
    assert len(appels_bcrypt) == 1


async def test_un_compte_desactive_fait_quand_meme_un_calcul_bcrypt(appels_bcrypt):
    service = AuthentificationService(FakeUserRepository([make_user(est_active=False)]))

    assert await service.authentifier("alice", "motdepasse123") is None
    assert len(appels_bcrypt) == 1


async def test_un_mauvais_mot_de_passe_est_refuse():
    service = AuthentificationService(FakeUserRepository([make_user()]))

    assert await service.authentifier("alice", "autre-mot-de-passe") is None


@pytest.mark.parametrize("login", ["alice", "inconnu"])
async def test_un_mot_de_passe_de_plus_de_72_octets_est_un_simple_echec(login):
    # bcrypt 5 lève une exception : elle ne doit pas devenir une erreur 500 (ni révéler le compte)
    service = AuthentificationService(FakeUserRepository([make_user()]))
    trop_long = "é" * 40  # 40 caractères mais 80 octets

    assert await service.authentifier(login, trop_long) is None


async def test_une_empreinte_invalide_en_base_est_un_simple_echec():
    service = AuthentificationService(
        FakeUserRepository([make_user(password_hash="pas-une-empreinte-bcrypt")])
    )

    assert await service.authentifier("alice", "motdepasse123") is None


async def test_admin_initial_refuse_un_mot_de_passe_de_plus_de_72_octets():
    service = AuthentificationService(FakeUserRepository())

    with pytest.raises(ValueError, match="trop long"):
        await service.creer_admin_initial("root", "a" * (MOT_DE_PASSE_MAX_OCTETS + 1))


async def test_admin_initial_accepte_exactement_72_octets():
    depot = FakeUserRepository()
    service = AuthentificationService(depot)

    assert await service.creer_admin_initial("root", "a" * MOT_DE_PASSE_MAX_OCTETS) is True
    assert "root" in depot.users