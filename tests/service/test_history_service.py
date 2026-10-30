from datetime import UTC, datetime

import pytest

from anonymia.service.business_objects.audit_entry import AuditEntry
from anonymia.service.business_objects.user import User
from anonymia.service.history_service import HistoryService
from tests.fakes import FakeArchiveRepository, FakeUserRepository


def entry(user_id, jour):
    return AuditEntry(
        user_id=user_id,
        date_traitement=datetime(2026, 10, jour, 12, 0, tzinfo=UTC),
        hash_document="h" * 64,
        strategie_anonymisation="masking",
        detecteurs_contributeurs="RegexDetector",
        nb_pii_detectees=1,
    )


def user(role, user_id=1):
    return User(id=user_id, login="u", password_hash="x", role=role)


@pytest.fixture
def archive():
    repo = FakeArchiveRepository()
    repo.entries = [entry(1, 10), entry(2, 20), entry(1, 25)]
    return repo


@pytest.fixture
def users():
    return FakeUserRepository([user("USER", 1), User(2, "bob", "x", "USER")])


@pytest.fixture
def service(archive, users):
    return HistoryService(archive, users)


@pytest.mark.parametrize("role", ["USER", "GUEST", ""])
async def test_les_autres_roles_sont_refuses(service, role):
    with pytest.raises(PermissionError):
        await service.get_history(user(role))


async def test_un_utilisateur_ne_peut_pas_consulter_meme_son_propre_historique(service):
    with pytest.raises(PermissionError):
        await service.get_history(user("USER", 1), login="u")


@pytest.mark.parametrize("role", ["SUPERVISOR", "ADMIN"])
async def test_superviseur_et_admin_voient_tout(service, role):
    result = await service.get_history(user(role))

    assert len(result) == 3


async def test_du_plus_recent_au_plus_ancien(service):
    result = await service.get_history(user("ADMIN"))

    assert [e.date_traitement.day for e in result] == [25, 20, 10]


async def test_filtre_par_login(service):
    result = await service.get_history(user("SUPERVISOR"), login="u")

    assert {e.user_id for e in result} == {1}
    assert len(result) == 2


async def test_login_inconnu_renvoie_une_liste_vide(service):
    result = await service.get_history(user("SUPERVISOR"), login="inconnu")

    assert result == []


async def test_filtre_par_periode(service):
    debut = datetime(2026, 10, 15, tzinfo=UTC)
    fin = datetime(2026, 10, 22, tzinfo=UTC)

    result = await service.get_history(user("SUPERVISOR"), date_debut=debut, date_fin=fin)

    assert [e.date_traitement.day for e in result] == [20]


async def test_les_dates_sans_fuseau_de_postgresql_sont_comparables(archive, service):
    # PostgreSQL renvoie des datetime sans fuseau : la comparaison ne doit pas planter
    archive.entries = [
        AuditEntry(1, datetime(2026, 10, 20, 12, 0), "h", "masking", "RegexDetector", 1)
    ]

    result = await service.get_history(user("ADMIN"), date_debut=datetime(2026, 10, 1, tzinfo=UTC))

    assert len(result) == 1