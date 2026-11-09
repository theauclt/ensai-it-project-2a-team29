"""Détecteur NER (spaCy) dans la composition root : construction et activation."""
from anonymia import dependencies
from anonymia.infrastructure.regex_detector import RegexDetector
from anonymia.infrastructure.spacy_detector import MODELE_PAR_DEFAUT
from tests.fakes import FakeArchiveRepository


class _FauxSpacyDetector:
    """Remplace SpacyDetector : enregistre le modèle demandé, sans charger de modèle."""

    modele_demande = None

    @classmethod
    def charger(cls, modele):
        cls.modele_demande = modele
        return cls()


def test_le_detecteur_ner_utilise_le_modele_de_la_variable_d_environnement(monkeypatch):
    monkeypatch.setattr(dependencies, "SpacyDetector", _FauxSpacyDetector)
    monkeypatch.setenv("SPACY_MODEL", "mon_modele_spacy")

    detecteur = dependencies.build_spacy_detector()

    assert isinstance(detecteur, _FauxSpacyDetector)
    assert _FauxSpacyDetector.modele_demande == "mon_modele_spacy"


def test_le_detecteur_ner_a_un_modele_par_defaut(monkeypatch):
    monkeypatch.setattr(dependencies, "SpacyDetector", _FauxSpacyDetector)
    monkeypatch.delenv("SPACY_MODEL", raising=False)

    dependencies.build_spacy_detector()

    assert _FauxSpacyDetector.modele_demande == MODELE_PAR_DEFAUT


def test_le_service_ajoute_le_detecteur_ner_quand_il_est_active(monkeypatch):
    ner = object()
    monkeypatch.setattr(dependencies, "build_spacy_detector", lambda: ner)

    avec = dependencies.build_detection_service(
        FakeArchiveRepository(), with_llm=False, with_ner=True
    )
    sans = dependencies.build_detection_service(
        FakeArchiveRepository(), with_llm=False, with_ner=False
    )

    assert [type(d) for d in avec._detectors] == [RegexDetector, object]
    assert avec._detectors[1] is ner
    assert [type(d) for d in sans._detectors] == [RegexDetector]