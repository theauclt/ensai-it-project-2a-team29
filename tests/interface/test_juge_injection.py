import sys
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx

# L'interface n'est pas un paquet : on ajoute son dossier au chemin, comme le fait Streamlit
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interface"))

import journal  # noqa: E402
from api_client import ApiClient  # noqa: E402

TZ = ZoneInfo("UTC")


def traitement(statut=None, type_=None):
    return {
        "id": 1,
        "user_id": 1,
        "date_traitement": "2026-11-04T12:00:00+00:00",
        "hash_document": "h" * 64,
        "strategie_anonymisation": "masking",
        "detecteurs_contributeurs": "RegexDetector,LLMDetector",
        "nb_pii_detectees": 2,
        "juge_statut": statut,
        "juge_type": type_,
    }


# ---------------------------------------------------------------------------
# Libellés et historique
# ---------------------------------------------------------------------------


def test_libelle_juge_distingue_les_trois_etats_et_l_absence():
    assert journal.libelle_juge("detected", "role_manipulation") == "Injection : Changement de rôle"
    assert journal.libelle_juge("not_detected") == "Rien repéré"
    assert journal.libelle_juge("unavailable") == "Indisponible"
    assert journal.libelle_juge(None) == "—"


def test_libelle_juge_type_inconnu_ne_plante_pas():
    assert journal.libelle_juge("detected", "nouveau_type") == "Injection : nouveau_type"
    assert journal.libelle_juge("detected", None) == "Injection : type inconnu"


def test_l_historique_et_le_csv_ont_la_colonne_du_juge():
    lignes = journal.lignes_tableau([traitement("detected", "other")], {}, TZ, hash_complet=True)

    assert lignes[0]["Juge LLM"] == "Injection : Autre tentative"
    assert "Juge LLM" in journal.vers_csv(lignes).decode("utf-8-sig").splitlines()[0]


def test_ancien_traitement_sans_champ_juge_ne_plante_pas():
    ancien = {k: v for k, v in traitement().items() if not k.startswith("juge_")}

    assert journal.lignes_tableau([ancien], {}, TZ)[0]["Juge LLM"] == "—"


def test_tableau_de_bord_compte_les_verdicts_du_juge():
    traitements = [
        traitement("detected", "other"),
        traitement("detected", "role_manipulation"),
        traitement("not_detected"),
        traitement("unavailable"),
        traitement(),
    ]

    synthese = journal.tableau_de_bord(traitements, {}, TZ)

    assert synthese["juge"] == {"detected": 2, "not_detected": 1, "unavailable": 1, "sans_juge": 1}


# ---------------------------------------------------------------------------
# Client de l'API
# ---------------------------------------------------------------------------


def client_api(corps):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=corps)

    return ApiClient("jeton", base_url="http://api.test", transport=httpx.MockTransport(handler))


def reponse_api(**extra):
    return {"document_caviarde": "texte", "confirmation_requise": False, **extra}


def test_le_client_transmet_le_verdict_du_juge():
    corps = reponse_api(juge={"statut": "detected", "type": "role_manipulation"})

    assert client_api(corps).caviarder("x", "masking")["juge"] == {"statut": "detected", "type": "role_manipulation"}


def test_le_client_sans_juge_donne_none():
    assert client_api(reponse_api()).caviarder("x", "masking")["juge"] is None
    assert client_api(reponse_api(juge=None)).caviarder("x", "masking")["juge"] is None


def test_le_client_ignore_un_verdict_illisible():
    assert client_api(reponse_api(juge={"statut": "peut-etre"})).caviarder("x", "masking")["juge"] is None
    assert client_api(reponse_api(juge="detected")).caviarder("x", "masking")["juge"] is None
