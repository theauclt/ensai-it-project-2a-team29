"""
Tests des dépôts PostgreSQL avec un faux pool de connexions : on vérifie les requêtes
envoyées et la validation ou l'annulation de la transaction, sans base de données réelle.
"""
import re
from datetime import UTC, datetime

import pytest
from psycopg.rows import dict_row

from anonymia.persistence.dao import db_connexion
from anonymia.persistence.postgres_archive_repository import PostgresArchiveRepository
from anonymia.persistence.postgres_user_repository import PostgresUserRepository
from anonymia.service.business_objects.audit_entry import AuditEntry
from tests.fakes import FakePool


@pytest.fixture
def pool():
    """Le pool factice et sa connexion, que les dépôts reçoivent à la construction."""
    return FakePool()


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


async def test_archive_enregistre_toutes_les_colonnes_dont_injection(pool):
    entree = AuditEntry(
        1, datetime(2026, 1, 1, tzinfo=UTC), "h" * 64, "masking", "RegexDetector", 2,
        injection_suspectee=True,
    )

    await PostgresArchiveRepository(pool).save(entree)

    requete, params = pool.connexion.requetes[0]
    # la colonne injection_suspectee reçoit True, quelle que soit sa position dans l'INSERT
    colonnes = re.search(r"\((.*?)\)\s*VALUES", requete, re.DOTALL).group(1)
    noms = [c.strip() for c in colonnes.split(",")]
    assert params[noms.index("injection_suspectee")] is True
    assert pool.connexion.commits == 1


async def test_archive_lit_par_utilisateur_et_en_entier(pool):
    pool.connexion.lignes = [LIGNE_TRAITEMENT]
    depot = PostgresArchiveRepository(pool)

    par_user = await depot.find_by_user(1)
    tout = await depot.find_all()

    assert pool.connexion.requetes[0][1] == (1,)
    assert par_user[0].id == 5
    assert par_user[0].injection_suspectee is True
    assert [e.nb_pii_detectees for e in tout] == [2]


# ---------------------------------------------------------------------------
# Comptes utilisateurs
# ---------------------------------------------------------------------------


async def test_user_recherches(pool):
    depot = PostgresUserRepository(pool)

    assert await depot.find_by_login("inconnu") is None
    assert await depot.find_by_id(9) is None

    pool.connexion.ligne = LIGNE_USER
    pool.connexion.lignes = [LIGNE_USER]
    assert (await depot.find_by_login("alice")).login == "alice"
    assert (await depot.find_by_id(1)).role == "USER"
    assert [u.id for u in await depot.find_all()] == [1]


async def test_user_ecritures_commit(pool):
    depot = PostgresUserRepository(pool)

    await depot.create("bob", "hash", "USER")
    await depot.update_role(1, "ADMIN")
    await depot.set_active(1, False)
    await depot.delete(1)

    assert pool.connexion.commits == 4
    assert pool.connexion.rollbacks == 0
    assert pool.connexion.requetes[0][0].startswith("INSERT INTO users")
    assert pool.connexion.requetes[3][0].startswith("DELETE FROM users")


async def test_user_ecriture_en_echec_fait_un_rollback_et_remonte(pool):
    pool.connexion.echec = True

    with pytest.raises(RuntimeError):
        await PostgresUserRepository(pool).create("bob", "hash", "USER")

    assert pool.connexion.rollbacks == 1
    assert pool.connexion.commits == 0


# ---------------------------------------------------------------------------
# Connexion
# ---------------------------------------------------------------------------


@pytest.fixture
def env_postgres(monkeypatch):
    for cle, valeur in {
        "HOST": "h", "PORT": "5432", "DATABASE": "d", "USER": "u", "PASSWORD": "p", "SCHEMA": "s",
    }.items():
        monkeypatch.setenv(f"POSTGRES_{cle}", valeur)


def test_parametres_de_connexion_lus_dans_l_environnement(env_postgres):
    parametres = db_connexion.parametres_connexion()

    assert (parametres["host"], parametres["port"], parametres["dbname"]) == ("h", "5432", "d")
    assert (parametres["user"], parametres["password"]) == ("u", "p")
    assert "-c search_path=s" in parametres["options"]
    # les dates sont stockées sans fuseau et relues comme de l'UTC : la session doit être en UTC
    assert "-c timezone=UTC" in parametres["options"]


def test_parametre_manquant_est_signale(env_postgres, monkeypatch):
    monkeypatch.delenv("POSTGRES_HOST")

    with pytest.raises(KeyError):
        db_connexion.parametres_connexion()


def test_le_pool_est_cree_ferme_et_renvoie_des_dictionnaires(env_postgres):
    pool = db_connexion.construire_pool()

    # ouvert plus tard, par le démarrage de l'API (await pool.open())
    assert pool.closed
    assert pool.kwargs["row_factory"] is dict_row
    assert pool.kwargs["options"] == db_connexion.parametres_connexion()["options"]
    assert (pool.min_size, pool.max_size) == (db_connexion.POOL_MIN, db_connexion.POOL_MAX)
