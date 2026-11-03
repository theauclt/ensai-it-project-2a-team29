"""
Gestion de la session de l'utilisateur dans Streamlit.

Rappel : Streamlit relance tout le script à chaque clic. Pour "se souvenir" de
l'utilisateur d'un clic à l'autre, on utilise st.session_state : un dictionnaire
propre à chaque onglet du navigateur, qui survit aux relances du script.
"""
import time

import jwt
import streamlit as st

_CLE = "session"

# Rôles autorisés à consulter l'historique. Ce n'est qu'un confort d'affichage :
# l'API refuse de toute façon l'accès aux autres rôles (erreur 403).
ROLES_HISTORIQUE = ("SUPERVISOR", "ADMIN")


def ouvrir(token: str) -> None:
    """Enregistre l'utilisateur connecté à partir du jeton renvoyé par l'API."""
    try:
        # On NE vérifie PAS la signature ici : l'interface n'a pas la clé secrète, et c'est
        # l'API qui vérifie le jeton à chaque requête. On lit seulement son contenu pour
        # savoir qui est connecté, quel est son rôle et quand le jeton expire.
        # Le rôle ne sert qu'à choisir les pages affichées : les droits réels restent
        # contrôlés par l'API.
        contenu = jwt.decode(token, options={"verify_signature": False})
        st.session_state[_CLE] = {
            "token": token,
            "login": contenu["login"],
            "role": contenu["role"],
            "expire_a": contenu["exp"],
        }
    except (jwt.PyJWTError, KeyError) as exc:
        raise ValueError("Jeton illisible : réessayez de vous connecter.") from exc


def courante() -> dict | None:
    """Renvoie la session de l'utilisateur connecté, ou None s'il ne l'est pas (ou plus)."""
    session = st.session_state.get(_CLE)
    if session is not None and session["expire_a"] <= time.time():
        # Le jeton dure 30 minutes : passé ce délai, l'API le refuserait de toute façon
        deconnecter()
        st.session_state["message_connexion"] = "Votre session a expiré, merci de vous reconnecter."
        return None
    return session


def exiger_connexion() -> dict:
    """À appeler en haut d'une page protégée : renvoie la session, ou renvoie à la connexion."""
    session = courante()
    if session is None:
        st.rerun()  # app.py reconstruit alors le menu avec la seule page de connexion
    return session


def afficher_erreur_api(erreur: Exception) -> None:
    """
    Affiche une erreur de l'API à l'utilisateur.

    Sur un 401 (jeton refusé ou expiré), on déconnecte et on renvoie à la connexion.
    """
    if getattr(erreur, "status_code", None) == 401:
        deconnecter()
        st.session_state["message_connexion"] = "Votre session n'est plus valide, merci de vous reconnecter."
        st.rerun()
    st.error(str(erreur))


def deconnecter() -> None:
    """Oublie l'utilisateur connecté."""
    st.session_state.pop(_CLE, None)
