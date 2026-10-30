from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from anonymia.infrastructure.anonymization_strategy_factory import AnonymizationStrategyFactory
from anonymia.infrastructure.regex_detector import RegexDetector
from anonymia.presentation.routes import routers
from anonymia.service.authentification_service import AuthentificationService
from anonymia.service.business_objects.audit_entry import AuditEntry
from anonymia.service.business_objects.user import User
from anonymia.service.detection_service import DetectionService
from anonymia.service.history_service import HistoryService
from tests.fakes import FakeArchiveRepository, FakeUserRepository

SECRET = "secret-de-test-assez-long-pour-hs256-0123456789"
MOT_DE_PASSE = "motdepasse123"
DOCUMENT = "Écrire à jean@mail.fr pour le dossier."


def make_user(id_, login, role, est_active=True):
    mdp_hash = bcrypt.hashpw(MOT_DE_PASSE.encode(), bcrypt.gensalt(rounds=4)).decode()
    return User(id_, login, mdp_hash, role, est_active)


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", SECRET)


@pytest.fixture
def archive():
    return FakeArchiveRepository()


@pytest.fixture
def client(archive):
    users = FakeUserRepository([
        make_user(1, "alice", "USER"),
        make_user(2, "sup", "SUPERVISOR"),
        make_user(3, "admin", "ADMIN"),
        make_user(4, "ancien", "USER", est_active=False),
    ])
    app = FastAPI()
    for router in routers:
        app.include_router(router)
    # Les services sont rangés dans app.state, comme le fait main.py au démarrage
    app.state.detection_service = DetectionService(
        [RegexDetector()], AnonymizationStrategyFactory(), archive
    )
    app.state.history_service = HistoryService(archive, users)
    app.state.auth_service = AuthentificationService(users)
    return TestClient(app)


def connecter(client, login, mot_de_passe=MOT_DE_PASSE):
    response = client.post(
        "/auth/connexion", json={"login": login, "mot_de_passe": mot_de_passe}
    )
    return response


def en_tete(client, login):
    token = connecter(client, login).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Connexion
# ---------------------------------------------------------------------------


def test_connexion_renvoie_un_jeton(client):
    response = connecter(client, "alice")

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    claims = jwt.decode(response.json()["access_token"], SECRET, algorithms=["HS256"])
    assert claims["login"] == "alice"
    assert claims["role"] == "USER"
    assert claims["sub"] == "1"


@pytest.mark.parametrize(
    ("login", "mot_de_passe"),
    [("alice", "mauvais"), ("inconnu", MOT_DE_PASSE), ("ancien", MOT_DE_PASSE)],
)
def test_connexion_refusee_avec_le_meme_message(client, login, mot_de_passe):
    response = connecter(client, login, mot_de_passe)

    assert response.status_code == 401
    assert response.json()["detail"] == "Identifiants invalides"


# ---------------------------------------------------------------------------
# Jeton
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", ["/documents/strategies", "/journaux"])
def test_sans_jeton_401(client, url):
    assert client.get(url).status_code == 401


def test_jeton_invalide_401(client):
    response = client.get("/documents/strategies", headers={"Authorization": "Bearer nimportequoi"})

    assert response.status_code == 401


def test_jeton_expire_401(client):
    expire = jwt.encode(
        {"sub": "1", "login": "alice", "role": "USER",
         "exp": datetime.now(UTC) - timedelta(minutes=1)},
        SECRET, algorithm="HS256",
    )

    response = client.get("/documents/strategies", headers={"Authorization": f"Bearer {expire}"})

    assert response.status_code == 401


def test_jeton_signe_avec_une_autre_cle_401(client):
    faux = jwt.encode(
        {"sub": "3", "login": "admin", "role": "ADMIN",
         "exp": datetime.now(UTC) + timedelta(minutes=5)},
        "une-autre-cle-de-signature-0123456789abcdef", algorithm="HS256",
    )

    response = client.get("/journaux", headers={"Authorization": f"Bearer {faux}"})

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


def test_analyser_renvoie_les_pii_avec_positions(client, archive):
    response = client.post(
        "/documents/analyser", json={"contenu": DOCUMENT}, headers=en_tete(client, "alice")
    )

    assert response.status_code == 200
    (pii,) = response.json()["pii"]
    assert pii["type"] == "EMAIL"
    assert DOCUMENT[pii["debut"]:pii["fin"]] == pii["texte"] == "jean@mail.fr"
    assert pii["detecteur"] == "RegexDetector"
    assert archive.entries == []  # analyser n'archive rien


def test_caviarder_masquage_et_archivage(client, archive):
    response = client.post(
        "/documents/caviarder",
        json={"contenu": DOCUMENT, "strategie": "masking"},
        headers=en_tete(client, "alice"),
    )

    assert response.status_code == 200
    assert response.json()["document_caviarde"] == "Écrire à [EMAIL_1] pour le dossier."
    (entree,) = archive.entries
    assert entree.user_id == 1  # l'identifiant vient du jeton, pas de la requête
    assert entree.strategie_anonymisation == "masking"


def test_caviarder_pseudonymisation(client):
    response = client.post(
        "/documents/caviarder",
        json={"contenu": DOCUMENT, "strategie": "pseudonymization"},
        headers=en_tete(client, "alice"),
    )

    assert response.json()["document_caviarde"] == (
        "Écrire à utilisateur1@example.com pour le dossier."
    )


def test_strategie_par_defaut_masquage(client):
    response = client.post(
        "/documents/caviarder", json={"contenu": DOCUMENT}, headers=en_tete(client, "alice")
    )

    assert "[EMAIL_1]" in response.json()["document_caviarde"]


def test_strategie_inconnue_400_sans_archivage(client, archive):
    response = client.post(
        "/documents/caviarder",
        json={"contenu": DOCUMENT, "strategie": "magie"},
        headers=en_tete(client, "alice"),
    )

    assert response.status_code == 400
    assert "masking" in response.json()["detail"]
    assert archive.entries == []


@pytest.mark.parametrize("corps", [{"contenu": ""}, {}, {"contenu": "x" * 100_001}])
def test_contenu_invalide_422(client, corps):
    response = client.post("/documents/caviarder", json=corps, headers=en_tete(client, "alice"))

    assert response.status_code == 422


def test_lister_les_strategies(client):
    response = client.get("/documents/strategies", headers=en_tete(client, "alice"))

    assert response.json() == {"strategies": ["masking", "pseudonymization"]}


# ---------------------------------------------------------------------------
# Journaux
# ---------------------------------------------------------------------------


def remplir(archive):
    for user_id, jour in [(1, 10), (2, 20), (1, 25)]:
        archive.entries.append(AuditEntry(
            user_id=user_id,
            date_traitement=datetime(2026, 10, jour, 12, 0, tzinfo=UTC),
            hash_document="h" * 64,
            strategie_anonymisation="masking",
            detecteurs_contributeurs="RegexDetector",
            nb_pii_detectees=1,
            id=len(archive.entries) + 1,
        ))


def test_un_utilisateur_simple_ne_peut_pas_consulter_les_journaux(client):
    response = client.get("/journaux", headers=en_tete(client, "alice"))

    assert response.status_code == 403


@pytest.mark.parametrize("login", ["sup", "admin"])
def test_superviseur_et_admin_consultent(client, archive, login):
    remplir(archive)

    response = client.get("/journaux", headers=en_tete(client, login))

    assert response.status_code == 200
    assert [t["id"] for t in response.json()] == [3, 2, 1]  # du plus récent au plus ancien


def test_filtre_par_utilisateur_et_periode(client, archive):
    remplir(archive)
    headers = en_tete(client, "sup")

    par_login = client.get("/journaux?utilisateur=alice", headers=headers).json()
    par_jours = client.get("/journaux?date_debut=2026-10-20&date_fin=2026-10-25", headers=headers)

    assert {t["user_id"] for t in par_login} == {1}
    assert [t["id"] for t in par_jours.json()] == [3, 2]  # le dernier jour est inclus


def test_les_journaux_ne_contiennent_jamais_le_contenu(client, archive):
    headers = en_tete(client, "sup")
    client.post("/documents/caviarder", json={"contenu": DOCUMENT}, headers=headers)

    response = client.get("/journaux", headers=headers)

    assert "jean@mail.fr" not in response.text
    assert "dossier" not in response.text
    assert set(response.json()[0]) == {
        "id", "user_id", "date_traitement", "hash_document",
        "strategie_anonymisation", "detecteurs_contributeurs", "nb_pii_detectees",
    }


def test_les_dates_sans_fuseau_de_la_base_sont_renvoyees_en_utc(client, archive):
    archive.entries.append(AuditEntry(
        1, datetime(2026, 10, 20, 12, 0), "h" * 64, "masking", "RegexDetector", 1, id=1
    ))

    response = client.get("/journaux", headers=en_tete(client, "sup"))

    assert response.json()[0]["date_traitement"].endswith(("Z", "+00:00"))