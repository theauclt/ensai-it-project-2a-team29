"""
Surlignage des données personnelles (PII) détectées dans un texte.

Ce module construit du HTML à partir du texte et de la liste de PII renvoyée par
l'API (champs texte, type, debut, fin, detecteur). Il n'importe pas Streamlit : il
peut donc être testé seul, avec de simples chaînes de caractères.

SÉCURITÉ : le texte du document est une donnée non fiable (il peut contenir du HTML ou
du JavaScript). Tout ce qui vient du document passe par html.escape avant d'être inséré
dans la page.
"""
import html

# type de PII -> (libellé affiché, couleur)
_STYLES = {
    "NOM": ("Nom", "#2563eb"),
    "PRENOM": ("Prénom", "#7c3aed"),
    "LIEU": ("Lieu", "#059669"),
    "ORGANISATION": ("Organisation", "#d97706"),
    "ADRESSE": ("Adresse", "#0d9488"),
    "DATE_NAISSANCE": ("Date de naissance", "#db2777"),
    "POSTE": ("Poste", "#64748b"),
    "EMAIL": ("E-mail", "#dc2626"),
    "TELEPHONE": ("Téléphone", "#ea580c"),
    "NIR": ("N° de sécurité sociale", "#9333ea"),
    "IBAN": ("IBAN", "#be123c"),
    "PLAQUE_ACTUELLE": ("Plaque", "#4f46e5"),
    "PLAQUE_ANCIENNE": ("Plaque", "#4f46e5"),
    "PLAQUE_DIPLOMATIQUE": ("Plaque", "#4f46e5"),
}
_STYLE_PAR_DEFAUT = (None, "#6b7280")  # type inconnu : libellé = le type lui-même, gris


def libelle(type_pii: str) -> str:
    """Nom lisible d'un type de PII (le type brut s'il est inconnu)."""
    return _STYLES.get(type_pii, _STYLE_PAR_DEFAUT)[0] or type_pii


def couleur(type_pii: str) -> str:
    """Couleur associée à un type de PII."""
    return _STYLES.get(type_pii, _STYLE_PAR_DEFAUT)[1]


def pii_surlignables(contenu: str, pii: list[dict]) -> list[dict]:
    """
    Garde les PII dont la position est cohérente avec le texte, triées et sans chevauchement.

    L'API renvoie déjà une liste propre ; ce filtre est une sécurité pour que l'affichage
    ne plante jamais (ni ne déforme le texte) si une position était aberrante.
    """
    retenues = []
    fin_precedente = 0
    for p in sorted(pii, key=lambda p: (p["debut"], -(p["fin"] - p["debut"]))):
        if 0 <= p["debut"] < p["fin"] <= len(contenu) and p["debut"] >= fin_precedente:
            retenues.append(p)
            fin_precedente = p["fin"]
    return retenues


def texte_surligne_html(contenu: str, pii: list[dict]) -> str:
    """Renvoie le texte en HTML, chaque PII surlignée et suivie de son type en petit."""
    morceaux = []
    position = 0
    for p in pii_surlignables(contenu, pii):
        c = couleur(p["type"])
        morceaux.append(html.escape(contenu[position : p["debut"]]))
        morceaux.append(
            f'<mark style="background:{c}33;border-bottom:2px solid {c};border-radius:3px;'
            f'padding:0 2px;color:inherit">{html.escape(contenu[p["debut"] : p["fin"]])}'
            f'<sup style="color:{c};font-size:0.65em;font-weight:600;margin-left:3px">'
            f"{html.escape(libelle(p['type']))}</sup></mark>"
        )
        position = p["fin"]
    morceaux.append(html.escape(contenu[position:]))

    # pre-wrap conserve les retours à la ligne et les espaces du document
    return (
        '<div style="white-space:pre-wrap;line-height:1.9;max-height:520px;overflow:auto;'
        'padding:12px 14px;border:1px solid rgba(128,128,128,0.35);border-radius:8px">'
        + "".join(morceaux)
        + "</div>"
    )


def legende_html(pii: list[dict]) -> str:
    """Renvoie la légende : une pastille par type de PII, avec le nombre d'occurrences."""
    compteurs: dict[str, int] = {}
    for p in pii:
        compteurs[p["type"]] = compteurs.get(p["type"], 0) + 1

    pastilles = []
    for type_pii, nombre in sorted(compteurs.items(), key=lambda t: (-t[1], t[0])):
        c = couleur(type_pii)
        pastilles.append(
            f'<span style="background:{c}33;border:1px solid {c};border-radius:12px;'
            f'padding:2px 10px;margin:0 6px 6px 0;display:inline-block;font-size:0.85em">'
            f"{html.escape(libelle(type_pii))} · {nombre}</span>"
        )
    return "<div>" + "".join(pastilles) + "</div>"
