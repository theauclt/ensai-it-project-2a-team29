"""SpacyDetector.charger : chemin nominal, avec un faux module spaCy (aucun modèle réel)."""
import sys
from types import SimpleNamespace

from anonymia.infrastructure.spacy_detector import (
    COMPOSANTS_INUTILES,
    MODELE_PAR_DEFAUT,
    SpacyDetector,
)


def _installer_faux_spacy(monkeypatch):
    appels = []
    faux_nlp = object()

    def load(modele, **options):
        appels.append((modele, options))
        return faux_nlp

    monkeypatch.setitem(sys.modules, "spacy", SimpleNamespace(load=load))
    return appels, faux_nlp


def test_charger_construit_un_detecteur_a_partir_du_modele(monkeypatch):
    appels, faux_nlp = _installer_faux_spacy(monkeypatch)

    detecteur = SpacyDetector.charger("mon_modele")

    assert isinstance(detecteur, SpacyDetector)
    assert detecteur._nlp is faux_nlp
    assert appels == [("mon_modele", {"exclude": COMPOSANTS_INUTILES})]


def test_charger_utilise_le_modele_par_defaut(monkeypatch):
    appels, _ = _installer_faux_spacy(monkeypatch)

    SpacyDetector.charger()

    assert appels[0][0] == MODELE_PAR_DEFAUT