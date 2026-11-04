"""
Tests complémentaires pour couvrir à 100 % le code qui retrouve les PII
dans le texte (RegexDetector, LLMDetector, DetectionService) : branches d'erreur
et garde-fous qui ne sont pas atteints par les cas nominaux.
"""
import json
import re
from types import SimpleNamespace

import httpx
import pytest

from anonymia.infrastructure import llm_detector as llm_module
from anonymia.infrastructure.anonymization_strategy_factory import (
    AnonymizationStrategyFactory,
)
from anonymia.infrastructure.llm_detector import (
    LLMDetector,
    LLMInvalidResponseError,
)
from anonymia.infrastructure.regex_detector import RegexDetector
from anonymia.service.detection_service import DetectionService
from anonymia.service.prompt_injector_detector import PromptInjectionDetector
from tests.fakes import FakeArchiveRepository


def make_detector(content_reponse) -> LLMDetector:
    def handler(request: httpx.Request) -> httpx.Response:
        body = {"choices": [{"message": {"content": content_reponse}}]}
        return httpx.Response(200, json=body)

    client = httpx.AsyncClient(
        base_url="http://llm.test/v1", transport=httpx.MockTransport(handler)
    )
    return LLMDetector(client=client, model="modele-test")


def brut(entites) -> str:
    return json.dumps({"entites": entites})


# ---------------------------------------------------------------------------
# RegexDetector
# ---------------------------------------------------------------------------


async def test_nir_sans_cle_de_controle_est_accepte():
    # 13 chiffres (la clé est facultative) : le format suffit
    spans = await RegexDetector().detect("NIR : 1 95 05 78 006 048")

    assert [s.type for s in spans] == ["NIR"]


@pytest.mark.parametrize("nir", ["ABCDEFGHIJKLM", "12345", ""])
def test_nir_invalide_est_refuse(nir):
    assert RegexDetector()._is_valid_nir(nir) is False


@pytest.mark.parametrize("numero", ["+", "abc", ""])
def test_numero_de_telephone_non_analysable_est_refuse(numero):
    assert RegexDetector()._is_valid_phonenumber(numero) is False


# ---------------------------------------------------------------------------
# LLMDetector : fermeture et vérificateur de sortie
# ---------------------------------------------------------------------------


async def test_aclose_ferme_le_client_http():
    detector = make_detector('{"entites": []}')

    await detector.aclose()

    assert detector._client.is_closed


@pytest.mark.parametrize(
    "entites",
    [
        ["Martin"],  # entité qui n'est pas un objet
        [{"texte": "Martin"}],  # champ "type" manquant
        [{"texte": "Martin", "type": "NOM", "extra": 1}],  # champ en trop
        [{"texte": 42, "type": "NOM"}],  # texte non textuel
        [{"texte": "Martin", "type": 7}],  # type non textuel
        [{"texte": "Martin", "type": "SUPER_ADMIN"}],  # type hors typologie
        [{"texte": "", "type": "NOM"}],  # texte vide
        [{"texte": " Martin", "type": "NOM"}],  # espaces autour
        [{"texte": "Dupont", "type": "NOM"}],  # absent du document
    ],
)
async def test_entites_invalides_declenchent_une_erreur(entites):
    detector = make_detector(brut(entites))

    with pytest.raises(LLMInvalidResponseError):
        await detector.detect("M. Martin")


async def test_entite_en_double_n_est_gardee_qu_une_fois():
    detector = make_detector(
        brut([{"texte": "Martin", "type": "NOM"}, {"texte": "Martin", "type": "NOM"}])
    )

    spans = await detector.detect("M. Martin")

    assert [(s.text, s.start, s.end) for s in spans] == [("Martin", 3, 9)]


async def test_cles_en_trop_dans_la_reponse_sont_refusees():
    detector = make_detector(json.dumps({"entites": [], "override": True}))

    with pytest.raises(LLMInvalidResponseError):
        await detector.detect("M. Martin")


# ---------------------------------------------------------------------------
# LLMDetector : garde-fous sur les positions (inatteignables en usage normal,
# car la recherche par expression régulière renvoie toujours le bon texte)
# ---------------------------------------------------------------------------


class _FauxMatch:
    def __init__(self, start, end):
        self._start, self._end = start, end

    def start(self):
        return self._start

    def end(self):
        return self._end


class _FauxPattern:
    def __init__(self, matches):
        self._matches = matches

    def finditer(self, _content):
        return iter(self._matches)


def _imposer_positions(monkeypatch, start, end):
    # On ne remplace que le module "re" vu par llm_detector : pytest garde le vrai
    faux_re = SimpleNamespace(
        escape=re.escape,
        compile=lambda *_a, **_k: _FauxPattern([_FauxMatch(start, end)]),
    )
    monkeypatch.setattr(llm_module, "re", faux_re)


def test_positions_hors_du_document_refusees(monkeypatch):
    _imposer_positions(monkeypatch, 5, 999)

    with pytest.raises(LLMInvalidResponseError, match="Positions"):
        LLMDetector._locate_spans([("Martin", "NOM")], "M. Martin")


def test_positions_qui_ne_correspondent_pas_au_texte_refusees(monkeypatch):
    _imposer_positions(monkeypatch, 0, 6)  # "M. Mar" au lieu de "Martin"

    with pytest.raises(LLMInvalidResponseError, match="Incohérence"):
        LLMDetector._locate_spans([("Martin", "NOM")], "M. Martin")


def test_texte_introuvable_refuse():
    with pytest.raises(LLMInvalidResponseError, match="localiser"):
        LLMDetector._locate_spans([("Dupont", "NOM")], "M. Martin")


def test_les_positions_renvoyees_designent_exactement_le_texte():
    content = "Martin et Mariette ; Martin, Marie."
    spans = LLMDetector._locate_spans([("Martin", "NOM"), ("Marie", "PRENOM")], content)

    assert [(s.text, s.start, s.end) for s in spans] == [
        ("Martin", 0, 6),
        ("Martin", 21, 27),
        ("Marie", 29, 34),
    ]
    assert all(content[s.start: s.end] == s.text for s in spans)
    assert re.fullmatch(r"\w+", spans[0].text)


# ---------------------------------------------------------------------------
# DetectionService : fermeture des détecteurs
# ---------------------------------------------------------------------------


async def test_aclose_ferme_les_detecteurs_qui_savent_se_fermer():
    class Fermable(RegexDetector):
        fermé = False

        async def aclose(self):
            self.fermé = True

    avec, sans = Fermable(), RegexDetector()  # sans : pas de méthode aclose
    service = DetectionService(
        [avec, sans],
        AnonymizationStrategyFactory(),
        FakeArchiveRepository(),
        PromptInjectionDetector(),
    )

    await service.aclose()

    assert avec.fermé is True