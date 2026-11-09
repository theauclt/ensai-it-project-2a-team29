import importlib.util
from types import SimpleNamespace

import pytest

from anonymia.infrastructure.anonymization_strategy_factory import AnonymizationStrategyFactory
from anonymia.infrastructure.regex_detector import RegexDetector
from anonymia.infrastructure.spacy_detector import (
    MODELE_PAR_DEFAUT,
    SpacyDetector,
    SpacyModeleIntrouvableError,
)
from anonymia.service.detection_service import DetectionService
from anonymia.service.prompt_injector_detector import PromptInjectionDetector
from tests.fakes import FakeArchiveRepository

TEXTE = "Claire Martin habite à Rennes et travaille chez Durand SA. Contact : claire@mail.fr"

# importlib.util sert à savoir si un module est importable sans l'importer


def entite(texte: str, label: str, contenu: str = TEXTE):
    """Fausse entité spaCy, positionnée comme le ferait le vrai modèle."""
    debut = contenu.index(texte)
    return SimpleNamespace(text=texte, label_=label, start_char=debut, end_char=debut + len(texte))


def make_detector(*entites) -> SpacyDetector:
    """SpacyDetector branché sur un faux pipeline : aucun modèle à télécharger."""

    def nlp(_contenu):
        return SimpleNamespace(ents=list(entites))

    return SpacyDetector(nlp)


async def test_convertit_les_etiquettes_spacy_en_types_anonymia():
    detector = make_detector(
        entite("Claire Martin", "PER"), entite("Rennes", "LOC"), entite("Durand SA", "ORG")
    )

    spans = await detector.detect(TEXTE)

    assert [(s.text, s.type) for s in spans] == [
        ("Claire Martin", "NOM"),
        ("Rennes", "LIEU"),
        ("Durand SA", "ORGANISATION"),
    ]
    assert {s.source_detector for s in spans} == {"SpacyDetector"}


async def test_les_positions_retrouvent_le_texte():
    spans = await make_detector(entite("Rennes", "LOC")).detect(TEXTE)

    assert TEXTE[spans[0].start : spans[0].end] == "Rennes"


async def test_ignore_misc_et_les_etiquettes_inconnues():
    detector = make_detector(entite("Claire Martin", "MISC"), entite("Rennes", "GPE"))

    assert await detector.detect(TEXTE) == []


async def test_ignore_une_entite_vide():
    vide = SimpleNamespace(text="  ", label_="PER", start_char=0, end_char=2)

    assert await make_detector(vide).detect(TEXTE) == []


@pytest.mark.parametrize("contenu", ["", "   \n\t"])
async def test_texte_vide_n_appelle_pas_le_modele(contenu):
    def nlp(_contenu):
        raise AssertionError("le modèle ne doit pas être appelé")

    assert await SpacyDetector(nlp).detect(contenu) == []


async def test_s_integre_au_service_de_detection():
    service = DetectionService(
        [RegexDetector(), make_detector(entite("Claire Martin", "PER"))],
        AnonymizationStrategyFactory(),
        FakeArchiveRepository(),
        PromptInjectionDetector(),
    )

    resultat = await service.detect(TEXTE, "masking", user_id=1)

    assert resultat.document.startswith("[NOM_1] habite")
    assert "[EMAIL_1]" in resultat.document
    assert "SpacyDetector" in resultat.detecteurs


def test_modele_introuvable_donne_un_message_d_installation():
    with pytest.raises(SpacyModeleIntrouvableError, match=r"spacy download"):
        SpacyDetector.charger("modele_qui_n_existe_pas")


@pytest.mark.skipif(
    importlib.util.find_spec(MODELE_PAR_DEFAUT) is None,
    reason="modèle spaCy non installé (python -m spacy download fr_core_news_lg)",
)
async def test_integration_avec_le_vrai_modele():
    detector = SpacyDetector.charger()
    texte = "Madame Claire Martin habite à Rennes et travaille chez Durand SA."

    spans = await detector.detect(texte)

    trouves = {(s.text, s.type) for s in spans}
    assert ("Claire Martin", "NOM") in trouves
    assert ("Rennes", "LIEU") in trouves
    assert ("Durand SA", "ORGANISATION") in trouves
    assert all(texte[s.start : s.end] == s.text for s in spans)