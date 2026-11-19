"""POST /auth/connexion : après trop d'échecs, la route répond 429 (audit ER3-02)."""
import bcrypt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from anonymia.presentation.routes import routers
from anonymia.service.authentification_service import AuthentificationService
from anonymia.service.business_objects.user import User
from anonymia.service.limiteur_connexions import LimiteurConnexions
from tests.fakes import FakeUserRepository

SECRET = "secret-de-test-assez-long-pour-hs256-0123456789"
MOT_DE_PASSE = "motdepasse123"


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", SECRET)


@pytest.fixture
def client():
    empreinte = bcrypt.hashpw(MOT_DE_PASSE.encode(), bcrypt.gensalt(rounds=4)).decode()
    utilisateurs = FakeUserRepository([User(1, "alice", empreinte, "USER"), User(2, "bob", empreinte, "USER")])
    app = FastAPI()
    for router in routers:
        app.include_router(router)
    app.state.auth_service = AuthentificationService(utilisateurs, LimiteurConnexions(max_echecs=3, verrouillage=600))
    return TestClient(app)


def connexion(client, login, mot_de_passe):
    return client.post("/auth/connexion", json={"login": login, "mot_de_passe": mot_de_passe})


def test_les_echecs_donnent_401_puis_la_route_se_bloque_en_429(client):
    assert [connexion(client, "alice", "mauvais").status_code for _ in range(3)] == [401, 401, 401]

    reponse = connexion(client, "alice", "mauvais")

    assert reponse.status_code == 429
    assert reponse.headers["Retry-After"] == "600"
    assert "10 minute" in reponse.json()["detail"]


def test_le_bon_mot_de_passe_est_refuse_pendant_le_blocage(client):
    for _ in range(3):
        connexion(client, "alice", "mauvais")

    assert connexion(client, "alice", MOT_DE_PASSE).status_code == 429


def test_le_blocage_ne_touche_pas_les_autres_comptes(client):
    for _ in range(3):
        connexion(client, "alice", "mauvais")

    assert connexion(client, "bob", MOT_DE_PASSE).status_code == 200


def test_un_login_inconnu_se_bloque_exactement_comme_un_login_existant(client):
    existant = [connexion(client, "alice", "mauvais").status_code for _ in range(4)]
    inconnu = [connexion(client, "fantome", "mauvais").status_code for _ in range(4)]

    assert existant == inconnu == [401, 401, 401, 429]  # rien ne révèle l'existence du compte


def test_avant_le_seuil_une_connexion_reussie_fonctionne_toujours(client):
    connexion(client, "alice", "mauvais")

    assert connexion(client, "alice", MOT_DE_PASSE).status_code == 200
