"""Composition root (dependencies.py) et démarrage de l'API (main.py)."""
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from anonymia import dependencies, main
from anonymia.infrastructure.llm_detector import LLMDetector
from anonymia.infrastructure.regex_detector import RegexDetector
from anonymia.service.authentification_service import AuthentificationService
from tests.fakes import FakeArchiveRepository, FakeUserRepository


@pytest.fixture
def faux_postgres(monkeypatch):
    """Les dépôts PostgreSQL sont remplacés par des dépôts en mémoire."""
    monkeypatch.setattr(dependencies, "PostgresArchiveRepository", FakeArchiveRepository)
    monkeypatch.setattr(dependencies, "PostgresUserRepository", FakeUserRepository)


def test_le_detecteur_llm_se_configure_par_variables_d_environnement(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://llm.test/v1")
    monkeypatch.setenv("LLM_MODEL", "mon-modele")
    monkeypatch.setenv("LLM_API_KEY", "cle")
    monkeypatch.setenv("LLM_TIMEOUT", "12")

    detecteur = dependencies.build_llm_detector()

    assert isinstance(detecteur, LLMDetector)
    assert detecteur._model == "mon-modele"
    assert detecteur._client.headers["Authorization"] == "Bearer cle"
    assert detecteur._client.timeout == httpx.Timeout(12.0)


def test_le_detecteur_llm_sans_cle_n_envoie_pas_d_en_tete_d_autorisation(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    assert "Authorization" not in dependencies.build_llm_detector()._client.headers


def test_mode_degrade_retire_le_detecteur_llm(faux_postgres):
    depot = dependencies.build_archive_repository()

    complet = dependencies.build_detection_service(depot, with_llm=True)
    degrade = dependencies.build_detection_service(depot, with_llm=False)

    assert [type(d).__name__ for d in complet._detectors] == ["RegexDetector", "LLMDetector"]
    assert [type(d) for d in degrade._detectors] == [RegexDetector]
    assert degrade._injection_detector is not None


def test_les_services_sont_assembles(faux_postgres):
    archive = dependencies.build_archive_repository()
    users = dependencies.build_user_repository()

    assert dependencies.build_history_service(archive, users) is not None
    assert isinstance(dependencies.build_auth_service(users), AuthentificationService)
    assert dependencies.build_admin_service(users) is not None


# ---------------------------------------------------------------------------
# Démarrage de l'application
# ---------------------------------------------------------------------------


@pytest.fixture
def demarrage(monkeypatch):
    """Remplace la construction des services par des versions en mémoire."""
    users = FakeUserRepository()
    fermetures = []

    class FauxDetection:
        async def aclose(self):
            fermetures.append("fermé")

    monkeypatch.setattr(main, "build_archive_repository", FakeArchiveRepository)
    monkeypatch.setattr(main, "build_user_repository", lambda: users)
    monkeypatch.setattr(
        main,
        "build_detection_service",
        lambda archive, **_options: FauxDetection(),
    )
    monkeypatch.setattr(main, "build_history_service", lambda a, u: SimpleNamespace())
    monkeypatch.setattr(main, "build_admin_service", lambda u: SimpleNamespace())
    monkeypatch.setenv("JWT_SECRET", "secret-de-test-assez-long-pour-hs256-0123456789")
    for cle in ("ADMIN_LOGIN", "ADMIN_PASSWORD"):
        monkeypatch.delenv(cle, raising=False)
    return SimpleNamespace(users=users, fermetures=fermetures)


def test_demarrage_sans_jwt_secret_echoue(demarrage, monkeypatch):
    monkeypatch.delenv("JWT_SECRET")

    with pytest.raises(RuntimeError, match="JWT_SECRET"), TestClient(main.app):
        pass


def test_demarrage_avec_un_secret_jwt_trop_court_echoue(demarrage, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "trop-court")

    with pytest.raises(RuntimeError, match="trop court"), TestClient(main.app):
        pass


def test_demarrage_range_les_services_et_ferme_le_llm_a_l_arret(demarrage):
    with TestClient(main.app) as client:
        assert main.app.state.auth_service is not None
        assert client.get("/", follow_redirects=False).status_code in (302, 307)

    assert demarrage.fermetures == ["fermé"]


def test_demarrage_cree_le_compte_administrateur_initial(demarrage, monkeypatch):
    monkeypatch.setenv("ADMIN_LOGIN", "root")
    monkeypatch.setenv("ADMIN_PASSWORD", "unmotdepasse1")

    with TestClient(main.app):
        pass

    assert "root" in demarrage.users.users
    assert demarrage.users.users["root"].role == "ADMIN"


def test_llm_desactive_par_variable_d_environnement(demarrage, monkeypatch):
    recu = {}
    monkeypatch.setattr(
        main,
        "build_detection_service",
        lambda archive, with_llm, **_options: recu.setdefault("with_llm", with_llm)
        or SimpleNamespace(aclose=_noop),
    )
    monkeypatch.setenv("LLM_ENABLED", "false")

    with TestClient(main.app):
        pass

    assert recu["with_llm"] is False


async def _noop():
    return None