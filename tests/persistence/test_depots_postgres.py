"""
Tests des dépôts PostgreSQL avec une fausse connexion : on vérifie les requêtes
envoyées et les commit/rollback, sans base de données réelle.
"""
import re
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from anonymia.persistence import postgres_archive_repository as archive_module
from anonymia.persistence import postgres_user_repository as user_module
from anonymia.persistence.dao import db_connexion
from anonymia.persistence.postgres_archive_repository import PostgresArchiveRepository
from anonymia.persistence.postgres_user_repository import PostgresUserRepository
from anonymia.service.business_objects.audit_entry import AuditEntry
from anonymia.utils.singleton import Singleton


class FakeCursor:
    def __init__(self, connexion):
        self.c = connexion

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, query, params=None):
        if self.c.echec:
            raise RuntimeError("erreur SQL")
        self.c.requetes.append((" ".join(query.split()), params))

    def fetchone(self):
        return self.c.ligne

    def fetchall(self):
        return self.c.lignes


class FakeConnexion:
    def __init__(self):
        self.requetes, self.commits, self.rollbacks = [], 0, 0
        self.ligne, self.lignes, self.echec = None, [], False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


@pytest.fixture
def connexion(monkeypatch):
    fausse = FakeConnexion()
    for module in (archive_module, user_module):
        monkeypatch.setattr(module, "DBConnection", lambda: SimpleNamespace(connection=fausse))
    return fausse


LIGNE_USER = {
    "id": 1, "username": "alice", "mdp_hash": "h", "role": "USER",
    "est_active": True, "date_creation": datetime(2026, 1, 1, tzinfo=UTC),
}
LIGNE_TRAITEMENT = {
    "id": 5, "user_id": 1, "date_traitement": datetime(2026, 1, 1, tzinfo=UTC),
    "hash_document": "h" * 64, "strategie_anonymisation": "masking",
    "detecteurs_contributeurs": "RegexDetector", "nb_pii_detectees": 2,
    "injection_suspectee": True,
}


# ---------------------------------------------------------------------------
# Archive des traitements
# ---------------------------------------------------------------------------


async def test_archive_enregistre_toutes_les_colonnes_dont_injection(connexion):
    entree = AuditEntry(
        1, datetime(2026, 1, 1, tzinfo=UTC), "h" * 64, "masking", "RegexDetector", 2,
        injection_suspectee=True,
    )

    await PostgresArchiveRepository().save(entree)

    requete, params = connexion.requetes[0]
    # la colonne injection_suspectee reçoit True, quelle que soit sa position dans l'INSERT
    colonnes = re.search(r"\((.*?)\)\s*VALUES", requete, re.DOTALL).group(1)
    noms = [c.strip() for c in colonnes.split(",")]
    assert params[noms.index("injection_suspectee")] is True
    assert connexion.commits == 1


async def test_archive_lit_par_utilisateur_et_en_entier(connexion):
    connexion.lignes = [LIGNE_TRAITEMENT]
    depot = PostgresArchiveRepository()

    par_user = await depot.find_by_user(1)
    tout = await depot.find_all()

    assert connexion.requetes[0][1] == (1,)
    assert par_user[0].id == 5
    assert par_user[0].injection_suspectee is True
    assert [e.nb_pii_detectees for e in tout] == [2]


# ---------------------------------------------------------------------------
# Comptes utilisateurs
# ---------------------------------------------------------------------------


async def test_user_recherches(connexion):
    depot = PostgresUserRepository()

    assert await depot.find_by_login("inconnu") is None
    assert await depot.find_by_id(9) is None

    connexion.ligne = LIGNE_USER
    connexion.lignes = [LIGNE_USER]
    assert (await depot.find_by_login("alice")).login == "alice"
    assert (await depot.find_by_id(1)).role == "USER"
    assert [u.id for u in await depot.find_all()] == [1]


async def test_user_ecritures_commit(connexion):
    depot = PostgresUserRepository()

    await depot.create("bob", "hash", "USER")
    await depot.update_role(1, "ADMIN")
    await depot.set_active(1, False)
    await depot.delete(1)

    assert connexion.commits == 4
    assert connexion.rollbacks == 0
    assert connexion.requetes[0][0].startswith("INSERT INTO users")
    assert connexion.requetes[3][0].startswith("DELETE FROM users")


async def test_user_ecriture_en_echec_fait_un_rollback_et_remonte(connexion):
    connexion.echec = True

    with pytest.raises(RuntimeError):
        await PostgresUserRepository().create("bob", "hash", "USER")

    assert connexion.rollbacks == 1
    assert connexion.commits == 0


# ---------------------------------------------------------------------------
# Connexion
# ---------------------------------------------------------------------------


def test_connexion_unique_autocommit(monkeypatch):
    monkeypatch.setitem(db_connexion.os.environ, "POSTGRES_HOST", "h")
    for cle, valeur in {"PORT": "5432", "DATABASE": "d", "USER": "u", "PASSWORD": "p", "SCHEMA": "s"}.items():
        monkeypatch.setenv(f"POSTGRES_{cle}", valeur)
    appels = []

    class Conn:
        autocommit = False

    def faux_connect(**kwargs):
        appels.append(kwargs)
        return Conn()

    monkeypatch.setattr(db_connexion.psycopg2, "connect", faux_connect)
    monkeypatch.setattr(Singleton, "_instances", {})

    a, b = db_connexion.DBConnection(), db_connexion.DBConnection()

    assert a is b and len(appels) == 1
    assert a.connection.autocommit is True
    assert appels[0]["options"] == "-c search_path=s"