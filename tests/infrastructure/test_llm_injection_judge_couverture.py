"""Branche de LLMInjectionJudge._parse_response non couverte : réponse JSON qui n'est pas un objet."""
import json

import httpx
import pytest

from anonymia.infrastructure.llm_injection_judge import LLMInjectionJudge


def make_judge(contenu: str) -> LLMInjectionJudge:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": contenu}}]})

    client = httpx.AsyncClient(
        base_url="http://llm.test/v1", transport=httpx.MockTransport(handler)
    )
    return LLMInjectionJudge(client=client, model="modele-test")


@pytest.mark.parametrize("contenu", ["[]", '"detected"', "42", "null"])
def test_une_reponse_qui_n_est_pas_un_objet_json_est_refusee(contenu):
    with pytest.raises(TypeError, match="objet JSON"):
        make_judge(contenu)._parse_response(contenu)


@pytest.mark.parametrize("contenu", ["[]", '"detected"', "42"])
async def test_le_juge_est_indisponible_si_la_reponse_n_est_pas_un_objet(contenu):
    verdict = await make_judge(contenu).analyze("Un document")

    assert verdict.status == "unavailable"
    assert verdict.injection_type is None


async def test_le_juge_est_indisponible_si_le_contenu_n_est_pas_du_json():
    verdict = await make_judge("pas du json").analyze("Un document")

    assert verdict.status == "unavailable"


async def test_verdict_valide_pour_reference():
    reponse = json.dumps(
        {"status": "not_detected", "injection_type": None, "explication": "rien"}
    )

    verdict = await make_judge(reponse).analyze("Un document")

    assert verdict.status == "not_detected"