from datetime import UTC, datetime

import pytest

from anonymia.persistence import postgres_archive_repository
from anonymia.persistence.postgres_archive_repository import PostgresArchiveRepository
from anonymia.service.business_objects.audit_entry import AuditEntry


class FakeCursor:
    def __init__(self, connexion):
        self.connexion = connexion

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query, params=None):
        self.connexion.requetes.append((" ".join(query.split()), params))

    def fetchall(self):
        return self.connexion.lignes


class FakeConnexion:
    def __init__(self, lignes=None):
        self.requetes = []
        self.lignes = lignes or []
        self.commits = 0

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1


@pytest.fixture
def connexion(monkeypatch):
    fausse = FakeConnexion()

    class FauxDBConnection:
        connection = fausse

    monkeypatch.setattr(postgres_archive_repository, "DBConnection", FauxDBConnection)
    return fausse


def entree(**kwargs):
    return AuditEntry(
        user_id=1,
        date_traitement=datetime(2026, 11, 4, 12, 0, tzinfo=UTC),
        hash_document="h" * 64,
        strategie_anonymisation="masking",
        detecteurs_contributeurs="RegexDetector,LLMDetector",
        nb_pii_detectees=2,
        **kwargs,
    )


async def test_save_enregistre_le_verdict_du_juge(connexion):
    repo = PostgresArchiveRepository()

    await repo.save(entree(types_pii="EMAIL:2", juge_statut="detected", juge_type="role_manipulation"))

    (requete, params), = connexion.requetes
    assert "juge_statut, juge_type" in requete
    assert requete.count("%s") == len(params) == 10
    assert params[-2:] == ("detected", "role_manipulation")
    assert connexion.commits == 1


async def test_save_sans_juge_enregistre_des_valeurs_nulles(connexion):
    await PostgresArchiveRepository().save(entree())

    assert connexion.requetes[0][1][-2:] == (None, None)


async def test_la_requete_n_enregistre_aucun_contenu(connexion):
    await PostgresArchiveRepository().save(entree(juge_statut="detected", juge_type="other"))

    requete = connexion.requetes[0][0]
    assert "explication" not in requete
    assert "contenu" not in requete


async def test_lecture_du_verdict_et_anciennes_lignes_sans_colonnes(connexion):
    base = {
        "id": 1, "user_id": 1, "date_traitement": datetime(2026, 11, 4), "hash_document": "h" * 64,
        "strategie_anonymisation": "masking", "detecteurs_contributeurs": "RegexDetector",
        "nb_pii_detectees": 1, "injection_suspectee": False,
    }
    connexion.lignes = [
        {**base, "types_pii": "EMAIL:1", "juge_statut": "unavailable", "juge_type": None},
        base,  # ligne d'avant l'ajout des colonnes
    ]

    nouveau, ancien = await PostgresArchiveRepository().find_all()

    assert (nouveau.juge_statut, nouveau.juge_type) == ("unavailable", None)
    assert (ancien.juge_statut, ancien.juge_type, ancien.types_pii) == (None, None, "")
