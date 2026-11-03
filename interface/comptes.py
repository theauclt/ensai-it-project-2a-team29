"""
Mise en forme et vérifications de saisie pour la gestion des comptes.

Ce module n'importe pas Streamlit : il se teste seul. Les vérifications de saisie ne sont qu'un
confort (message immédiat, sans appel réseau) : l'API revérifie tout et reste l'autorité.
"""
from datetime import tzinfo

import journal

ROLES = ("USER", "SUPERVISOR", "ADMIN")
LIBELLES_ROLES = {"USER": "Utilisateur", "SUPERVISOR": "Superviseur", "ADMIN": "Administrateur"}

# Mêmes règles que l'API (service/mots_de_passe.py et schemas.py)
MOT_DE_PASSE_MIN = 8
MOT_DE_PASSE_MAX = 128
LOGIN_MAX = 255

COLONNES = ["Identifiant", "Rôle", "Statut", "Créé le", "N°"]


def libelle_role(role: str) -> str:
    """Nom lisible d'un rôle (le rôle brut s'il est inconnu)."""
    return LIBELLES_ROLES.get(role, role)


def libelle_compte(compte: dict) -> str:
    """Texte affiché dans la liste de choix, par exemple 'alice : Utilisateur, actif'."""
    statut = "actif" if compte["est_active"] else "désactivé"
    return f"{compte['login']} : {libelle_role(compte['role'])}, {statut}"


def verifier_creation(login: str, mot_de_passe: str, confirmation: str) -> str | None:
    """Message d'erreur à afficher, ou None si la saisie est acceptable."""
    login = login.strip()
    if not login:
        return "Renseignez un identifiant."
    if len(login) > LOGIN_MAX:
        return f"L'identifiant est trop long ({LOGIN_MAX} caractères maximum)."
    if len(mot_de_passe) < MOT_DE_PASSE_MIN:
        return f"Le mot de passe doit faire au moins {MOT_DE_PASSE_MIN} caractères."
    if len(mot_de_passe) > MOT_DE_PASSE_MAX:
        return f"Le mot de passe est trop long ({MOT_DE_PASSE_MAX} caractères maximum)."
    if mot_de_passe != confirmation:
        return "Les deux mots de passe ne sont pas identiques."
    return None


def suppression_confirmee(saisie: str, login: str) -> bool:
    """La suppression n'est lancée que si l'on a retapé exactement l'identifiant du compte."""
    return saisie.strip() == login


def trier(comptes: list[dict]) -> list[dict]:
    """Comptes triés par identifiant, sans tenir compte de la casse."""
    return sorted(comptes, key=lambda c: c["login"].casefold())


def lignes_tableau(comptes: list[dict], tz: tzinfo, mon_login: str) -> list[dict]:
    """Une ligne par compte, avec les colonnes de COLONNES. Votre propre compte est signalé."""
    return [
        {
            "Identifiant": c["login"] + (" (vous)" if c["login"] == mon_login else ""),
            "Rôle": libelle_role(c["role"]),
            "Statut": "Actif" if c["est_active"] else "Désactivé",
            "Créé le": journal.formater_date(c.get("date_creation"), tz),
            "N°": c["id"],
        }
        for c in trier(comptes)
    ]


def resume(comptes: list[dict]) -> str:
    """Phrase de synthèse affichée au-dessus du tableau."""
    actifs = [c for c in comptes if c["est_active"]]
    admins = [c for c in actifs if c["role"] == "ADMIN"]
    pluriel = "s" if len(comptes) > 1 else ""
    return (
        f"{len(comptes)} compte{pluriel}, dont {len(actifs)} actif{'s' if len(actifs) > 1 else ''} "
        f"et {len(admins)} administrateur{'s' if len(admins) > 1 else ''} actif{'s' if len(admins) > 1 else ''}."
    )
