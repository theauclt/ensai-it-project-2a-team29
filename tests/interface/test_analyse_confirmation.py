"""ER1-01 : le client de l'interface gère la confirmation de /documents/analyser."""
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "interface"))

from api_client import ApiClient, ApiError  # noqa: E402


def client_avec(reponse: httpx.Response, envoyes: list):
    def gestionnaire(requete: httpx.Request) -> httpx.Response:
        envoyes.append((requete.url.path, json.loads(requete.content)))
        return reponse

    return ApiClient(token="jeton", base_url="http://api", transport=httpx.MockTransport(gestionnaire))


def test_analyser_envoie_confirmer_faux_par_defaut():
    envoyes = []
    client = client_avec(httpx.Response(200, json={"pii": []}), envoyes)

    client.analyser("texte")

    assert envoyes == [("/documents/analyser", {"contenu": "texte", "confirmer": False})]


def test_analyser_avec_confirmation_envoie_confirmer_vrai():
    envoyes = []
    client = client_avec(httpx.Response(200, json={"pii": []}), envoyes)

    client.analyser("texte", confirmer=True)

    assert envoyes[0][1]["confirmer"] is True


def test_analyser_lit_la_confirmation_requise():
    corps = {
        "pii": [],
        "confirmation_requise": True,
        "types_injection": ["instruction_override"],
        "avertissements": ["Il n'a pas été traité."],
    }
    reponse = client_avec(httpx.Response(200, json=corps), []).analyser("texte")

    assert reponse["confirmation_requise"] is True
    assert reponse["pii"] == []
    assert reponse["types_injection"] == ["instruction_override"]
    assert reponse["juge"] is None


def test_analyser_lit_les_pii_et_le_juge():
    corps = {
        "pii": [{"texte": "a@b.fr", "type": "EMAIL", "debut": 0, "fin": 6,
                 "detecteur": "RegexDetector", "confiance": 1.0}],
        "mode_degrade": True,
        "juge": {"statut": "not_detected", "type": None},
    }
    reponse = client_avec(httpx.Response(200, json=corps), []).analyser("a@b.fr")

    assert reponse["confirmation_requise"] is False
    assert reponse["pii"][0]["type"] == "EMAIL"
    assert reponse["mode_degrade"] is True
    assert reponse["juge"] == {"statut": "not_detected", "type": None}


def test_analyser_sans_pii_ni_confirmation_est_une_reponse_invalide():
    with pytest.raises(ApiError):
        client_avec(httpx.Response(200, json={"detecteurs": []}), []).analyser("texte")


def test_analyser_compte_desactive_leve_une_erreur_403():
    client = client_avec(httpx.Response(403, json={"detail": "Compte désactivé : 10 documents suspects"}), [])

    with pytest.raises(ApiError) as erreur:
        client.analyser("texte")

    assert erreur.value.status_code == 403