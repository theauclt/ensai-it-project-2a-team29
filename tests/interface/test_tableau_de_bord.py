import sys
from pathlib import Path

# L'interface n'est pas un paquet : on ajoute son dossier au chemin, comme le fait Streamlit
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interface"))

from zoneinfo import ZoneInfo

import journal

TZ = ZoneInfo("UTC")


def traitement(user_id, jour, strategie="masking", detecteurs="RegexDetector,LLMDetector", nb=3):
    return {
        "id": 1,
        "user_id": user_id,
        "date_traitement": f"2026-10-{jour:02d}T12:00:00+00:00",
        "hash_document": "h" * 64,
        "strategie_anonymisation": strategie,
        "detecteurs_contributeurs": detecteurs,
        "nb_pii_detectees": nb,
    }


def test_liste_vide():
    synthese = journal.tableau_de_bord([], {}, TZ)

    assert synthese["traitements"] == 0
    assert synthese["pii_moyenne"] == 0.0
    assert synthese["part_sans_llm"] == 0
    assert synthese["par_utilisateur"] == {}


def test_chiffres_cles():
    traitements = [traitement(1, 10, nb=2), traitement(2, 10, nb=5), traitement(1, 11, nb=2)]

    synthese = journal.tableau_de_bord(traitements, {}, TZ)

    assert synthese["traitements"] == 3
    assert synthese["pii"] == 9
    assert synthese["utilisateurs"] == 2
    assert synthese["pii_moyenne"] == 3.0
    assert synthese["par_jour"] == {"2026-10-10": 2, "2026-10-11": 1}


def test_repartition_par_utilisateur_triee_avec_logins():
    traitements = [traitement(1, 10), traitement(2, 10), traitement(2, 11), traitement(2, 12)]

    synthese = journal.tableau_de_bord(traitements, {2: "alice"}, TZ)

    assert list(synthese["par_utilisateur"].items()) == [("alice", 3), ("n°1", 1)]


def test_repartition_par_strategie_et_detecteurs():
    traitements = [
        traitement(1, 10, strategie="masking"),
        traitement(1, 10, strategie="pseudonymization", detecteurs="RegexDetector"),
        traitement(1, 10, strategie="masking"),
    ]

    synthese = journal.tableau_de_bord(traitements, {}, TZ)

    assert synthese["par_strategie"] == {"Masquage": 2, "Pseudonymisation": 1}
    assert synthese["par_detecteurs"] == {"Regex + LLM": 2, "Regex seul": 1}


def test_traitements_sans_llm():
    traitements = [
        traitement(1, 10, detecteurs="RegexDetector"),
        traitement(1, 10, detecteurs="RegexDetector,LLMDetector"),
        traitement(1, 10, detecteurs="RegexDetector"),
        traitement(1, 10, detecteurs="RegexDetector,LLMDetector"),
    ]

    synthese = journal.tableau_de_bord(traitements, {}, TZ)

    assert synthese["sans_llm"] == 2
    assert synthese["part_sans_llm"] == 50
