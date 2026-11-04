import sys
from pathlib import Path

# L'interface n'est pas un paquet : on ajoute son dossier au chemin, comme le fait Streamlit
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interface"))

import surlignage  # noqa: E402

PII = [{"texte": "Martin", "type": "NOM", "debut": 0, "fin": 6, "detecteur": "LLMDetector", "confiance": 0.95}]


def test_libelle_confiance():
    assert surlignage.libelle_confiance(0.95) == "95 %"
    assert surlignage.libelle_confiance(1.0) == "100 %"
    assert surlignage.libelle_confiance(None) == "—"


def test_le_tableau_affiche_la_confiance():
    html = surlignage.tableau_pii_html(PII)

    assert "Confiance" in html
    assert "95 %" in html


def test_le_surlignage_donne_la_confiance_au_survol():
    html = surlignage.texte_surligne_html("Martin est là.", PII)

    assert 'title="Confiance : 95 %"' in html


def test_reponse_sans_confiance_ne_plante_pas():
    ancienne = [{k: v for k, v in PII[0].items() if k != "confiance"}]

    assert "—" in surlignage.tableau_pii_html(ancienne)
    assert "Confiance : —" in surlignage.texte_surligne_html("Martin est là.", ancienne)
