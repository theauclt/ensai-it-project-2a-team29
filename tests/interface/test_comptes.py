import sys
from pathlib import Path

# L'interface n'est pas un paquet : on ajoute son dossier au chemin, comme le fait Streamlit
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interface"))

from zoneinfo import ZoneInfo

import comptes

TZ = ZoneInfo("UTC")


def compte(login, tentatives=0, dangereux=False, actif=True, role="USER", id_=1):
    return {
        "id": id_,
        "login": login,
        "role": role,
        "est_active": actif,
        "date_creation": None,
        "tentatives_injection": tentatives,
        "comportement_dangereux": dangereux,
    }


def test_le_tableau_affiche_les_tentatives_et_l_alerte():
    lignes = comptes.lignes_tableau(
        [compte("alice", 4, True), compte("bob", 1, id_=2)], TZ, "admin"
    )

    assert list(lignes[0]) == comptes.COLONNES
    alice, bob = lignes
    assert (alice["Alerte"], alice["Tentatives d'injection"]) == (comptes.ALERTE_DANGER, 4)
    assert (bob["Alerte"], bob["Tentatives d'injection"]) == ("", 1)


def test_une_ancienne_api_sans_compteur_affiche_zero():
    ancien = {"id": 1, "login": "alice", "role": "USER", "est_active": True}

    ligne = comptes.lignes_tableau([ancien], TZ, "admin")[0]

    assert (ligne["Alerte"], ligne["Tentatives d'injection"]) == ("", 0)
    assert comptes.est_signale(ancien) is False


def test_le_libelle_signale_un_compte_dangereux():
    assert comptes.libelle_compte(compte("alice", 3, True)) == "alice : Utilisateur, actif ⚠️"
    assert comptes.libelle_compte(compte("bob")) == "bob : Utilisateur, actif"


def test_les_comptes_signales_sont_tries_par_nombre_de_tentatives():
    liste = [compte("bob", 3, True), compte("alice", 10, True, actif=False), compte("carole", 2)]

    assert [c["login"] for c in comptes.signales(liste)] == ["alice", "bob"]


def test_l_avertissement_resume_les_comptes_signales():
    liste = [compte("bob", 3, True), compte("alice", 10, True, actif=False), compte("carole", 2)]

    message = comptes.avertissement_signales(liste)

    assert message.startswith("Comportement dangereux : 2 comptes signalés")
    assert "alice (10 tentatives, désactivé)" in message
    assert "bob (3 tentatives)" in message
    assert "carole" not in message


def test_pas_d_avertissement_sans_compte_signale():
    assert comptes.avertissement_signales([compte("alice", 2)]) is None
