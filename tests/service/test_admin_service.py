import pytest

from anonymia.service.admin_service import (
    AdminService,
    CompteIntrouvableError,
    DonneeInvalideError,
    LoginDejaPrisError,
    OperationInterditeError,
)
from anonymia.service.business_objects.user import User
from tests.fakes import FakeUserRepository


def compte(id_, login, role="USER", est_active=True):
    return User(id_, login, "hash", role, est_active)


@pytest.fixture
def repo():
    return FakeUserRepository([
        compte(1, "admin", "ADMIN"),
        compte(2, "admin2", "ADMIN"),
        compte(3, "alice", "USER"),
        compte(4, "sup", "SUPERVISOR"),
    ])


@pytest.fixture
def service(repo):
    return AdminService(repo)


@pytest.fixture
def admin(repo):
    return repo.users["admin"]


# --- droits -----------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["USER", "SUPERVISOR"])
async def test_refuse_aux_non_administrateurs(service, role):
    demandeur = compte(9, "x", role)

    with pytest.raises(PermissionError):
        await service.lister(demandeur)
    with pytest.raises(PermissionError):
        await service.creer(demandeur, "n", "motdepasse123", "USER")
    with pytest.raises(PermissionError):
        await service.changer_role(demandeur, 3, "ADMIN")
    with pytest.raises(PermissionError):
        await service.definir_activation(demandeur, 3, False)
    with pytest.raises(PermissionError):
        await service.supprimer(demandeur, 3)


@pytest.mark.asyncio
async def test_lister(service, admin):
    assert [u.login for u in await service.lister(admin)] == ["admin", "admin2", "alice", "sup"]


# --- création ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_creer(service, repo, admin):
    nouveau = await service.creer(admin, " bob ", "motdepasse123", "supervisor")

    assert nouveau.login == "bob"
    assert nouveau.role == "SUPERVISOR"
    assert nouveau.est_active is True
    assert nouveau.password_hash != "motdepasse123"
    assert repo.users["bob"] is nouveau


@pytest.mark.asyncio
async def test_creer_login_deja_pris(service, admin):
    with pytest.raises(LoginDejaPrisError):
        await service.creer(admin, "alice", "motdepasse123", "USER")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("login", "mot_de_passe", "role"),
    [("bob", "court", "USER"), ("bob", "motdepasse123", "ROOT"), ("  ", "motdepasse123", "USER")],
)
async def test_creer_donnees_invalides(service, repo, admin, login, mot_de_passe, role):
    with pytest.raises(DonneeInvalideError):
        await service.creer(admin, login, mot_de_passe, role)
    assert len(repo.users) == 4


# --- rôle -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_changer_role(service, admin):
    modifie = await service.changer_role(admin, 3, "supervisor")

    assert modifie.role == "SUPERVISOR"


@pytest.mark.asyncio
async def test_changer_role_invalide_ou_inconnu(service, admin):
    with pytest.raises(DonneeInvalideError):
        await service.changer_role(admin, 3, "ROOT")
    with pytest.raises(CompteIntrouvableError):
        await service.changer_role(admin, 99, "USER")


@pytest.mark.asyncio
async def test_admin_ne_peut_pas_se_retirer_son_role(service, admin):
    with pytest.raises(OperationInterditeError):
        await service.changer_role(admin, admin.id, "USER")


@pytest.mark.asyncio
async def test_retirer_le_role_dun_autre_admin(service, admin):
    modifie = await service.changer_role(admin, 2, "USER")

    assert modifie.role == "USER"


@pytest.mark.asyncio
async def test_dernier_admin_actif_protege_pour_le_role(repo, admin):
    # admin2 est désactivé : admin est le seul administrateur actif
    repo.users["admin2"].est_active = False
    demandeur = compte(2, "admin2", "ADMIN")  # un admin (jeton) qui rétrograde admin
    service = AdminService(repo)

    with pytest.raises(OperationInterditeError):
        await service.changer_role(demandeur, admin.id, "USER")


# --- activation -------------------------------------------------------------


@pytest.mark.asyncio
async def test_desactiver_puis_reactiver(service, admin):
    assert (await service.definir_activation(admin, 3, False)).est_active is False
    assert (await service.definir_activation(admin, 3, True)).est_active is True


@pytest.mark.asyncio
async def test_admin_ne_peut_pas_se_desactiver(service, admin):
    with pytest.raises(OperationInterditeError):
        await service.definir_activation(admin, admin.id, False)


@pytest.mark.asyncio
async def test_dernier_admin_actif_protege_pour_la_desactivation(repo, admin):
    repo.users["admin2"].est_active = False
    service = AdminService(repo)
    demandeur = compte(2, "admin2", "ADMIN")

    with pytest.raises(OperationInterditeError):
        await service.definir_activation(demandeur, admin.id, False)


@pytest.mark.asyncio
async def test_activation_compte_inconnu(service, admin):
    with pytest.raises(CompteIntrouvableError):
        await service.definir_activation(admin, 99, False)


# --- suppression ------------------------------------------------------------


@pytest.mark.asyncio
async def test_supprimer(service, repo, admin):
    await service.supprimer(admin, 3)

    assert "alice" not in repo.users


@pytest.mark.asyncio
async def test_supprimer_inconnu(service, admin):
    with pytest.raises(CompteIntrouvableError):
        await service.supprimer(admin, 99)


@pytest.mark.asyncio
async def test_admin_ne_peut_pas_se_supprimer(service, admin):
    with pytest.raises(OperationInterditeError):
        await service.supprimer(admin, admin.id)


@pytest.mark.asyncio
async def test_dernier_admin_actif_protege_pour_la_suppression(repo, admin):
    repo.users["admin2"].est_active = False
    service = AdminService(repo)
    demandeur = compte(2, "admin2", "ADMIN")

    with pytest.raises(OperationInterditeError):
        await service.supprimer(demandeur, admin.id)
