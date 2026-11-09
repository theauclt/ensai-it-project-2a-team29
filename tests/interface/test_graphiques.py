import sys
from pathlib import Path

# L'interface n'est pas un paquet : on ajoute son dossier au chemin, comme le fait Streamlit
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interface"))

import graphiques


def test_les_graphiques_se_construisent():
    repartition = {"alice": 3, "n°2": 1}

    for graphique in (
        graphiques.barres_horizontales(repartition, "Utilisateur"),
        graphiques.barres_verticales(repartition, "Jour"),
        graphiques.anneau(repartition, "Stratégie"),
    ):
        assert graphique.to_dict()["$schema"]  # spécification Vega-Lite valide


def test_la_part_est_calculee_en_pourcentage():
    donnees = graphiques._donnees({"a": 3, "b": 1}, "Cat")

    assert [d["Part"] for d in donnees] == ["75 %", "25 %"]


def test_repartition_vide_ne_plante_pas():
    assert graphiques._donnees({}, "Cat") == []
