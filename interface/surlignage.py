"""
Mise en forme des données personnelles (PII) dans un texte.

Ce module construit du HTML à partir du texte et de la liste de PII renvoyée par
l'API (champs texte, type, debut, fin, detecteur), ou à partir du texte d'origine et
du texte caviardé. Il n'importe pas Streamlit : il peut donc être testé seul, avec de
simples chaînes de caractères. Les classes CSS utilisées (an-pii, an-masque...) sont
définies dans theme.py.

SÉCURITÉ : le texte du document est une donnée non fiable (il peut contenir du HTML ou
du JavaScript). Tout ce qui vient du document passe par html.escape avant d'être inséré
dans la page.
"""
import difflib
import html
import re

# type de PII -> libellé affiché
_LIBELLES = {
    "NOM": "Nom",
    "PRENOM": "Prénom",
    "LIEU": "Lieu",
    "ORGANISATION": "Organisation",
    "ADRESSE": "Adresse",
    "DATE_NAISSANCE": "Date de naissance",
    "POSTE": "Poste",
    "EMAIL": "E-mail",
    "TELEPHONE": "Téléphone",
    "NIR": "N° de sécurité sociale",
    "IBAN": "IBAN",
    "PLAQUE_ACTUELLE": "Plaque",
    "PLAQUE_ANCIENNE": "Plaque",
    "PLAQUE_DIPLOMATIQUE": "Plaque",
}

_LIBELLES_DETECTEURS = {"RegexDetector": "Règles", "LLMDetector": "LLM"}

# Marqueur posé par la stratégie de masquage : [EMAIL_1], [NOM_2]...
_MARQUEUR = re.compile(r"\[[A-Z][A-Z_]*_\d+\]")
# Découpage en mots pour comparer le texte d'origine et le texte caviardé
_JETONS = re.compile(r"\[[A-Z][A-Z_]*_\d+\]|\s+|\w+|[^\w\s]")


def _nombre(n: int) -> str:
    """Entier avec une espace fine comme séparateur de milliers (12 345)."""
    return f"{n:,}".replace(",", " ")


def libelle(type_pii: str) -> str:
    """Nom lisible d'un type de PII (le type brut s'il est inconnu)."""
    return _LIBELLES.get(type_pii, type_pii)


def libelle_detecteur(detecteur: str) -> str:
    """Nom court d'un détecteur (le nom brut s'il est inconnu)."""
    return _LIBELLES_DETECTEURS.get(detecteur, detecteur)


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


def libelle_confiance(confiance: float | None) -> str:
    """Confiance affichée en pourcentage (« 95 % »), ou un tiret si l'API ne la fournit pas."""
    return "—" if confiance is None else f"{round(100 * confiance)} %"


def texte_surligne_html(contenu: str, pii: list[dict]) -> str:
    """Renvoie le texte en HTML, chaque PII surlignée et suivie de son type en petit."""
    morceaux = []
    position = 0
    for p in pii_surlignables(contenu, pii):
        morceaux.append(html.escape(contenu[position : p["debut"]]))
        titre = f"Confiance : {libelle_confiance(p.get('confiance'))}"
        morceaux.append(
            f'<mark class="an-pii" title="{html.escape(titre)}">{html.escape(contenu[p["debut"] : p["fin"]])}'
            f"<sup>{html.escape(libelle(p['type']))}</sup></mark>"
        )
        position = p["fin"]
    morceaux.append(html.escape(contenu[position:]))
    return '<div class="an-page" tabindex="0" aria-label="Texte analysé">' + "".join(morceaux) + "</div>"


def compter_types(pii: list[dict]) -> list[tuple[str, int]]:
    """Nombre d'occurrences par libellé de type, du plus fréquent au plus rare."""
    compteurs: dict[str, int] = {}
    for p in pii:
        nom = libelle(p["type"])
        compteurs[nom] = compteurs.get(nom, 0) + 1
    return sorted(compteurs.items(), key=lambda t: (-t[1], t[0]))


def types_html(pii: list[dict]) -> str:
    """Résumé en une ligne : chaque type de PII suivi de son nombre d'occurrences."""
    elements = "".join(f"<span>{html.escape(nom)}<b>{nombre}</b></span>" for nom, nombre in compter_types(pii))
    return f'<div class="an-types">{elements}</div>'


def tableau_pii_html(pii: list[dict]) -> str:
    """Tableau des PII détectées : texte, type, détecteur, confiance et position dans le document."""
    lignes = "".join(
        "<tr>"
        f'<td class="id">{html.escape(p["texte"])}</td>'
        f"<td>{html.escape(libelle(p['type']))}</td>"
        f"<td>{html.escape(libelle_detecteur(p['detecteur']))}</td>"
        f'<td class="droite">{libelle_confiance(p.get("confiance"))}</td>'
        f'<td class="droite">{_nombre(p["debut"])}–{_nombre(p["fin"])}</td>'
        "</tr>"
        for p in sorted(pii, key=lambda p: p["debut"])
    )
    return (
        '<div class="an-defile"><table class="an-tableau"><thead><tr>'
        '<th style="width:40%">Texte détecté</th><th>Type</th><th>Détecteur</th><th class="droite">Confiance</th><th class="droite">Position</th>'
        f"</tr></thead><tbody>{lignes}</tbody></table></div>"
    )


# ----------------------------------------------------------------------
# Texte caviardé
# ----------------------------------------------------------------------

def _separateur(jetons: list[str]) -> bool:
    """Vrai pour un court passage sans mot ni retour à la ligne (une espace, un point, un @)."""
    texte = "".join(jetons)
    return 0 < len(texte) <= 3 and "\n" not in texte and not any(re.match(r"\w", j) for j in jetons)


def _regrouper(operations: list[tuple], b: list[str]) -> list[tuple]:
    """
    Fusionne les remplacements voisins que seul un séparateur identique sépare.

    Sans cela, « Claire Martin » remplacé par « Paul Renaud » donnerait deux remplacements
    (l'espace entre les deux mots est identique dans les deux textes), et une adresse e-mail
    en donnerait cinq.
    """
    resultat: list[list] = []
    for k, (operation, i1, i2, j1, j2) in enumerate(operations):
        change = operation != "equal"
        entre_deux = (
            not change
            and resultat
            and resultat[-1][0] != "equal"
            and k + 1 < len(operations)
            and operations[k + 1][0] != "equal"
            and _separateur(b[j1:j2])
        )
        if (change or entre_deux) and resultat and resultat[-1][0] != "equal":
            resultat[-1][2], resultat[-1][4] = i2, j2
        else:
            resultat.append([operation, i1, i2, j1, j2])
    return [tuple(o) for o in resultat]


def remplacements(contenu: str, caviarde: str) -> list[tuple[str, str | None]]:
    """
    Découpe le texte caviardé en morceaux (texte, original).

    original vaut None pour un morceau identique au texte d'origine ; sinon c'est le passage
    d'origine que ce morceau remplace. L'API ne renvoie que le texte caviardé : on retrouve
    les remplacements en comparant les deux textes mot à mot.
    """
    a = _JETONS.findall(contenu)
    b = _JETONS.findall(caviarde)
    morceaux: list[tuple[str, str | None]] = []
    for operation, i1, i2, j1, j2 in _regrouper(difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes(), b):
        nouveau = "".join(b[j1:j2])
        if operation == "equal":
            morceaux.append((nouveau, None))
        elif nouveau:
            # Les espaces autour d'un remplacement restent du texte ordinaire
            debut = len(nouveau) - len(nouveau.lstrip())
            fin = len(nouveau.rstrip())
            if debut:
                morceaux.append((nouveau[:debut], None))
            if nouveau.strip():
                morceaux.append((nouveau[debut:fin], "".join(a[i1:i2]).strip()))
            if fin < len(nouveau):
                morceaux.append((nouveau[fin:], None))
    return morceaux


def liste_remplacements(contenu: str, caviarde: str) -> list[tuple[str, str]]:
    """Paires (passage d'origine, remplacement), dans l'ordre du document."""
    return [(original, texte) for texte, original in remplacements(contenu, caviarde) if original]


def _marque(texte: str) -> str:
    """Un remplacement mis en forme : trait d'encre pour un marqueur, soulignement sinon."""
    classe = "an-masque" if _MARQUEUR.fullmatch(texte) else "an-pseudo"
    return f'<span class="{classe}">{html.escape(texte)}</span>'


def _marquer(texte: str) -> str:
    """Met en forme les marqueurs contenus dans un passage, le reste en texte souligné."""
    if not _MARQUEUR.search(texte):
        return _marque(texte)
    morceaux, position = [], 0
    for m in _MARQUEUR.finditer(texte):
        morceaux.append(html.escape(texte[position : m.start()]))
        morceaux.append(_marque(m.group()))
        position = m.end()
    morceaux.append(html.escape(texte[position:]))
    return "".join(morceaux)


def texte_caviarde_html(contenu: str, caviarde: str) -> str:
    """Renvoie le texte caviardé en HTML, chaque remplacement mis en évidence."""
    corps = "".join(
        html.escape(texte) if original is None else _marquer(texte) for texte, original in remplacements(contenu, caviarde)
    )
    return f'<div class="an-page" tabindex="0" aria-label="Document caviardé">{corps}</div>'


def tableau_remplacements_html(paires: list[tuple[str, str]]) -> str:
    """Tableau des remplacements : passage d'origine et ce qui le remplace."""
    lignes = "".join(
        f'<tr><td class="id">{html.escape(original)}</td><td class="fleche">→</td><td>{_marquer(texte)}</td></tr>'
        for original, texte in paires
    )
    return (
        '<div class="an-defile"><table class="an-tableau"><thead><tr>'
        '<th style="width:46%">Texte d\'origine</th><th style="width:28px"></th><th>Remplacé par</th>'
        f"</tr></thead><tbody>{lignes}</tbody></table></div>"
    )


def page_vide_html() -> str:
    """Volet de résultat avant tout traitement : une esquisse de page et la marche à suivre."""
    return (
        '<div class="an-page vide"><div class="an-esquisse" aria-hidden="true">'
        '<i style="width:92%"></i><i style="width:78%"></i><i class="c" style="width:44%"></i>'
        '<i style="width:86%"></i><i style="width:64%"></i></div>'
        "<strong>Aucun résultat pour l'instant</strong>"
        "<span>Analysez le texte pour voir les données personnelles repérées, "
        "ou caviardez-le pour obtenir la version à diffuser.</span></div>"
    )
