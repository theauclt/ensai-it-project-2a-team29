import sys
from pathlib import Path

# L'interface n'est pas un paquet : on ajoute son dossier au chemin, comme le fait Streamlit
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interface"))

from zoneinfo import ZoneInfo

import journal

TZ = ZoneInfo("UTC")


def traitement(injection=None, nb=3):
    t = {
        "id": 1,
        "user_id": 7,
        "date_traitement": "2026-10-12T09:30:00+00:00",
        "hash_document": "a" * 64,
        "strategie_anonymisation": "masking",
        "detecteurs_contributeurs": "RegexDetector,LLMDetector",
        "nb_pii_detectees": nb,
    }
    if injection is not None:
        t["injection_suspectee"] = injection
    return t


def test_la_colonne_injection_est_dans_le_tableau():
    lignes = journal.lignes_tableau([traitement(True), traitement(False)], {}, TZ)

    assert "Injection suspectée" in journal.COLONNES
    assert [ligne["Injection suspectée"] for ligne in lignes] == [True, False]


def test_un_ancien_traitement_sans_le_champ_n_est_pas_suspect():
    ligne = journal.lignes_tableau([traitement()], {}, TZ)[0]

    assert ligne["Injection suspectée"] is False


def test_statistiques_comptent_les_injections():
    stats = journal.statistiques([traitement(True), traitement(False), traitement(True), traitement()], TZ)

    assert stats["injections"] == 2


def test_csv_ecrit_oui_ou_non():
    lignes = journal.lignes_tableau([traitement(True), traitement(False)], {}, TZ, hash_complet=True)
    texte = journal.vers_csv(lignes).decode("utf-8-sig").splitlines()

    entete = texte[0].split(";")
    colonne = entete.index("Injection suspectée")
    assert [ligne.split(";")[colonne] for ligne in texte[1:]] == ["Oui", "Non"]
