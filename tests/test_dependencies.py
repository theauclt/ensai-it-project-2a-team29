import pytest

from anonymia import dependencies
from anonymia.infrastructure.llm_detector import LLMDetector
from anonymia.infrastructure.llm_injection_judge import LLMInjectionJudge
from tests.fakes import FakeArchiveRepository


@pytest.fixture(autouse=True)
def env_propre(monkeypatch):
    for nom in ("LLM_JUDGE_ENABLED", "LLM_JUDGE_MODEL"):
        monkeypatch.delenv(nom, raising=False)
    monkeypatch.setenv("LLM_MODEL", "modele-detecteur")


def llm_et_juge(service):
    detecteur = next(d for d in service._detectors if isinstance(d, LLMDetector))
    return detecteur, service._injection_judge


async def test_par_defaut_le_juge_partage_le_client_du_detecteur():
    service = dependencies.build_detection_service(FakeArchiveRepository())

    detecteur, juge = llm_et_juge(service)

    assert isinstance(juge, LLMInjectionJudge)
    assert juge.client is detecteur._client
    assert juge.model == "modele-detecteur"
    await service.aclose()  # ferme le client partagé deux fois sans erreur


async def test_modele_du_juge_configurable(monkeypatch):
    monkeypatch.setenv("LLM_JUDGE_MODEL", "modele-juge")

    service = dependencies.build_detection_service(FakeArchiveRepository())

    assert service._injection_judge.model == "modele-juge"
    await service.aclose()


async def test_juge_desactive_par_la_configuration(monkeypatch):
    monkeypatch.setenv("LLM_JUDGE_ENABLED", "false")

    service = dependencies.build_detection_service(FakeArchiveRepository())

    assert service._injection_judge is None
    await service.aclose()


async def test_sans_llm_il_n_y_a_pas_de_juge():
    service = dependencies.build_detection_service(FakeArchiveRepository(), with_llm=False)

    assert service._injection_judge is None
    assert not any(isinstance(d, LLMDetector) for d in service._detectors)
