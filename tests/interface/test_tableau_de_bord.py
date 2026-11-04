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


def test_maximum_et_tranches():
    traitements = [traitement(1, 10, nb=0), traitement(1, 10, nb=2), traitement(1, 10, nb=3), traitement(1, 10, nb=11)]

    synthese = journal.tableau_de_bord(traitements, {}, TZ)

    assert synthese["pii_max"] == 11
    assert synthese["par_tranche"] == {"0": 1, "1 à 2": 1, "3 à 5": 1, "6 à 10": 0, "Plus de 10": 1}


def test_detail_par_utilisateur():
    traitements = [traitement(1, 10, nb=2), traitement(1, 12, nb=4), traitement(2, 11, nb=6)]

    detail = journal.tableau_de_bord(traitements, {1: "alice"}, TZ)["detail_utilisateurs"]

    assert [ligne["Utilisateur"] for ligne in detail] == ["alice", "n°2"]
    assert detail[0]["Traitements"] == 2
    assert detail[0]["Données détectées"] == 6
    assert detail[0]["Moyenne par document"] == 3.0
    assert detail[0]["Dernier traitement"].day == 12


# ---------------------------------------------------------------------------
# Types de données (F4)
# ---------------------------------------------------------------------------


def avec_types(types, nb=None, user_id=1):
    t = traitement(user_id, 10, nb=sum(types.values()) if nb is None else nb)
    t["types_pii"] = types
    return t


def test_libelle_types_lisible_et_trie():
    assert journal.libelle_types({"NOM": 1, "EMAIL": 2}) == "2 E-mail · 1 Nom"
    assert journal.libelle_types({}) == "—"
    assert journal.libelle_types(None) == "—"


def test_les_trois_types_de_plaques_s_additionnent():
    assert journal.regrouper_types({"PLAQUE_ACTUELLE": 1, "PLAQUE_ANCIENNE": 2}) == {"Plaque": 3}


def test_historique_et_csv_ont_la_colonne_des_types():
    lignes = journal.lignes_tableau([avec_types({"EMAIL": 2})], {}, TZ, hash_complet=True)

    assert lignes[0]["Types de données"] == "2 E-mail"
    assert "Types de données" in journal.vers_csv(lignes).decode("utf-8-sig").splitlines()[0]


def test_repartition_par_type_sur_tous_les_traitements():
    traitements = [avec_types({"EMAIL": 2, "NOM": 1}), avec_types({"EMAIL": 1}), avec_types({"IBAN": 1})]

    synthese = journal.tableau_de_bord(traitements, {}, TZ)

    assert synthese["par_type"] == {"E-mail": 3, "IBAN": 1, "Nom": 1}
    assert synthese["traitements_sans_types"] == 0


def test_anciens_traitements_sans_types_sont_comptes_a_part():
    ancien = traitement(1, 10, nb=4)  # enregistré avant l'ajout des types : pas de champ types_pii
    vide = avec_types({}, nb=0)  # nouveau traitement sans aucune donnée : ce n'est pas un ancien

    synthese = journal.tableau_de_bord([ancien, vide, avec_types({"NOM": 1})], {}, TZ)

    assert synthese["par_type"] == {"Nom": 1}
    assert synthese["traitements_sans_types"] == 1
