"""
Client HTTP de l'API Anonymia.

C'est le SEUL fichier de l'interface qui parle à l'API : les pages Streamlit
appellent les méthodes de ApiClient et ne font jamais de requête HTTP elles-mêmes.
Ainsi, si l'API change, un seul fichier est à modifier.
"""
import os
from datetime import date

import httpx

# Adresse de l'API. Par défaut celle de `uvicorn anonymia.main:app` lancé en local.
# Pour viser une autre adresse : API_URL=http://... streamlit run interface/app.py
API_URL = os.environ.get("API_URL", "http://localhost:8000")

# Le LLM peut mettre plusieurs secondes à répondre : on prévoit un délai large
TIMEOUT_SECONDES = 90


class ApiError(Exception):
    """Erreur de l'API, avec un message lisible à afficher tel quel à l'utilisateur."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ApiClient:
    """Petit wrapper autour de httpx pour appeler l'API Anonymia."""

    def __init__(self, token: str | None = None, base_url: str = API_URL, transport: httpx.BaseTransport | None = None):
        """
        token     : jeton JWT de l'utilisateur connecté (None avant la connexion).
        transport : réservé aux tests (permet de simuler l'API sans réseau).
        """
        self._token = token
        self._base_url = base_url
        self._transport = transport

    def connexion(self, login: str, mot_de_passe: str) -> str:
        """POST /auth/connexion : renvoie le jeton JWT si les identifiants sont bons."""
        reponse = self._requete("POST", "/auth/connexion", json={"login": login, "mot_de_passe": mot_de_passe})
        try:
            return reponse.json()["access_token"]
        except (ValueError, KeyError) as exc:
            raise ApiError("Réponse inattendue de l'API.") from exc

    def strategies(self) -> list[str]:
        """GET /documents/strategies : noms des stratégies de caviardage disponibles."""
        reponse = self._requete("GET", "/documents/strategies")
        return self._champ(reponse, "strategies")

    def analyser(self, contenu: str) -> list[dict]:
        """
        POST /documents/analyser : liste des PII détectées.

        Chaque élément est un dictionnaire avec les clés texte, type, debut, fin, detecteur.
        Aucune trace n'est archivée côté API pour une simple analyse.
        """
        reponse = self._requete("POST", "/documents/analyser", json={"contenu": contenu})
        return self._champ(reponse, "pii")

    def caviarder(self, contenu: str, strategie: str) -> str:
        """POST /documents/caviarder : renvoie le document caviardé (le traitement est archivé)."""
        reponse = self._requete(
            "POST", "/documents/caviarder", json={"contenu": contenu, "strategie": strategie}
        )
        return self._champ(reponse, "document_caviarde")

    def journaux(
        self,
        utilisateur: str | None = None,
        date_debut: date | None = None,
        date_fin: date | None = None,
    ) -> list[dict]:
        """
        GET /journaux : historique des traitements, du plus récent au plus ancien.

        Réservé aux rôles SUPERVISOR et ADMIN (sinon ApiError 403). Les filtres sont facultatifs :
        utilisateur (login) et jours de début et de fin (inclus, comptés en UTC par l'API).
        """
        parametres = {}
        if utilisateur:
            parametres["utilisateur"] = utilisateur
        if date_debut:
            parametres["date_debut"] = date_debut.isoformat()
        if date_fin:
            parametres["date_fin"] = date_fin.isoformat()
        reponse = self._requete("GET", "/journaux", params=parametres)
        return self._liste(reponse)

    def utilisateurs(self) -> list[dict]:
        """GET /admin/utilisateurs : liste des comptes (réservé aux ADMIN, sinon ApiError 403)."""
        return self._liste(self._requete("GET", "/admin/utilisateurs"))

    def creer_utilisateur(self, login: str, mot_de_passe: str, role: str) -> dict:
        """POST /admin/utilisateurs : crée un compte (ADMIN). Erreurs : 409 si le login existe, 400 si invalide."""
        reponse = self._requete(
            "POST", "/admin/utilisateurs", json={"login": login, "mot_de_passe": mot_de_passe, "role": role}
        )
        return self._objet(reponse)

    def changer_role(self, user_id: int, role: str) -> dict:
        """PATCH /admin/utilisateurs/{id}/role : change le rôle d'un compte (ADMIN)."""
        reponse = self._requete("PATCH", f"/admin/utilisateurs/{user_id}/role", json={"role": role})
        return self._objet(reponse)

    def definir_activation(self, user_id: int, est_active: bool) -> dict:
        """PATCH /admin/utilisateurs/{id}/activation : désactive ou réactive un compte (ADMIN)."""
        reponse = self._requete("PATCH", f"/admin/utilisateurs/{user_id}/activation", json={"est_active": est_active})
        return self._objet(reponse)

    def supprimer_utilisateur(self, user_id: int) -> None:
        """DELETE /admin/utilisateurs/{id} : supprime le compte ET ses traitements archivés (ADMIN)."""
        self._requete("DELETE", f"/admin/utilisateurs/{user_id}")

    # ------------------------------------------------------------------
    # Outils internes
    # ------------------------------------------------------------------

    @staticmethod
    def _objet(reponse: httpx.Response) -> dict:
        """Lit une réponse JSON qui doit être un objet, avec un message clair sinon."""
        try:
            donnees = reponse.json()
        except ValueError as exc:
            raise ApiError("Réponse inattendue de l'API.") from exc
        if not isinstance(donnees, dict):
            raise ApiError("Réponse inattendue de l'API.")
        return donnees

    @staticmethod
    def _liste(reponse: httpx.Response) -> list[dict]:
        """Lit une réponse JSON qui doit être une liste, avec un message clair sinon."""
        try:
            donnees = reponse.json()
        except ValueError as exc:
            raise ApiError("Réponse inattendue de l'API.") from exc
        if not isinstance(donnees, list):
            raise ApiError("Réponse inattendue de l'API.")
        return donnees

    @staticmethod
    def _champ(reponse: httpx.Response, nom: str):
        """Lit un champ de la réponse JSON, avec un message clair si elle est inattendue."""
        try:
            return reponse.json()[nom]
        except (ValueError, KeyError, TypeError) as exc:
            raise ApiError("Réponse inattendue de l'API.") from exc

    def _requete(self, methode: str, chemin: str, **kwargs) -> httpx.Response:
        """Envoie une requête (avec le jeton s'il existe) et traduit les erreurs en ApiError."""
        entetes = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        try:
            with httpx.Client(base_url=self._base_url, timeout=TIMEOUT_SECONDES, transport=self._transport) as client:
                reponse = client.request(methode, chemin, headers=entetes, **kwargs)
        except httpx.TimeoutException as exc:
            raise ApiError(
                "L'API a mis trop de temps à répondre (le LLM est peut-être lent). Réessayez."
            ) from exc
        except httpx.HTTPError as exc:
            raise ApiError("Impossible de joindre l'API. Est-elle bien lancée ?") from exc

        if reponse.is_error:
            raise ApiError(self._message_erreur(reponse), reponse.status_code)
        return reponse

    @staticmethod
    def _message_erreur(reponse: httpx.Response) -> str:
        """Extrait un message lisible d'une réponse d'erreur de FastAPI."""
        try:
            detail = reponse.json()["detail"]
        except (ValueError, KeyError, TypeError):
            return f"Erreur {reponse.status_code} de l'API."

        if isinstance(detail, str):
            return detail
        if isinstance(detail, list):
            # Erreur de validation (422). On n'affiche que les messages, jamais les
            # valeurs envoyées : elles pourraient contenir le texte du document.
            messages = [str(e.get("msg", "")) for e in detail if isinstance(e, dict)]
            return "Données invalides : " + " ; ".join(m for m in messages if m)
        return f"Erreur {reponse.status_code} de l'API."
