"""
Page Caviardage : saisir ou importer un texte, voir les données personnelles détectées,
puis obtenir le texte caviardé.

Mise en page : à gauche le document source, à droite le résultat (texte analysé ou
caviardé), et en dessous le détail des détections ou des remplacements.

Deux situations sont signalées par un bandeau au-dessus des volets :
- le mode dégradé : le LLM n'a pas répondu, seules les règles automatiques ont tourné ;
- l'injection de prompt : le texte contient des consignes destinées au LLM. Le caviardage
  est alors suspendu par l'API jusqu'à ce que l'utilisateur confirme.

Rappel Streamlit : le script est relancé à chaque clic. Ce qui doit survivre d'un clic
à l'autre (le texte, le dernier résultat) est donc rangé dans st.session_state.
"""
import html

import session
import streamlit as st
import surlignage
import theme
from api_client import ApiClient, ApiError

MAX_CARACTERES = 100_000  # limite de l'API pour un document

LIBELLES_STRATEGIES = {
    "masking": "Masquage",
    "pseudonymization": "Pseudonymisation",
}
AIDES_STRATEGIES = {
    "masking": "Chaque donnée est remplacée par un marqueur : [EMAIL_1], [NOM_2]…",
    "pseudonymization": "Chaque donnée est remplacée par une valeur fictive du même type.",
}

# Catégories renvoyées par le filtre d'injection (service/prompt_injector_detector.py)
LIBELLES_INJECTION = {
    "instruction_override": "Contournement des consignes",
    "role_manipulation": "Changement de rôle",
    "prompt_extraction": "Extraction du prompt",
    "data_exfiltration": "Exfiltration de données",
}

EXEMPLE = (
    "Bonjour, je m'appelle Claire Martin, née le 23 septembre 1984 à Nantes.\n"
    "Vous pouvez me joindre à claire.martin@laposte.net ou au 06 12 34 56 78.\n"
    "Mon IBAN : FR1420041010050500013M02606."
)

utilisateur = session.exiger_connexion()
client = ApiClient(utilisateur["token"])

st.session_state.setdefault("contenu", "")
st.session_state.setdefault("upload_n", 0)  # change pour vider le sélecteur de fichier


def _nombre(n: int) -> str:
    """Entier avec une espace fine comme séparateur de milliers (12 345)."""
    return f"{n:,}".replace(",", " ")


def _pluriel(n: int, mot: str) -> str:
    return f"{_nombre(n)} {mot}{'s' if n > 1 else ''}"


def _categories(types_injection: list[str]) -> list[str]:
    return [LIBELLES_INJECTION.get(t, t) for t in types_injection]


def _donnees(n: int) -> str:
    s = "s" if n > 1 else ""
    return f"{_nombre(n)} donnée{s} personnelle{s}"


# ----------------------------------------------------------------------
# Actions des boutons (callbacks : exécutés AVANT la relance du script)
# C'est le seul endroit où l'on peut modifier la valeur d'un champ déjà affiché.
# ----------------------------------------------------------------------

def _importer_fichier() -> None:
    """Charge le fichier choisi dans la zone de texte."""
    st.session_state.pop("erreur_import", None)
    fichier = st.session_state.get(f"fichier_{st.session_state['upload_n']}")
    if fichier is None:
        return
    try:
        texte = fichier.getvalue().decode("utf-8-sig")
    except UnicodeDecodeError:
        st.session_state["erreur_import"] = "Ce fichier n'est pas encodé en UTF-8 : enregistrez-le dans cet encodage."
        return
    if not texte.strip():
        st.session_state["erreur_import"] = "Le fichier est vide."
    elif len(texte) > MAX_CARACTERES:
        st.session_state["erreur_import"] = (
            f"Le fichier fait {_nombre(len(texte))} caractères ; la limite est de {_nombre(MAX_CARACTERES)}."
        )
    else:
        st.session_state["contenu"] = texte


def _inserer_exemple() -> None:
    st.session_state["contenu"] = EXEMPLE


def _annuler_confirmation() -> None:
    st.session_state.pop("resultat", None)


def _effacer() -> None:
    """Vide le texte, le résultat et le fichier importé."""
    st.session_state["contenu"] = ""
    st.session_state.pop("resultat", None)
    st.session_state.pop("erreur_import", None)
    st.session_state["upload_n"] += 1


# ----------------------------------------------------------------------
# Affichage
# ----------------------------------------------------------------------

def _entete_volet(titre: str, meta: str = "", pastille: str = "") -> None:
    """En-tête d'un volet : son titre à gauche, une précision ou un avertissement à droite."""
    droite = f'<span class="an-pastille">{pastille}</span>' if pastille else f'<span class="an-meta">{meta}</span>'
    st.html(f'<div class="an-volet"><h2>{titre}</h2>{droite}</div>')


def _bandeaux(resultat: dict) -> None:
    """Avertissements à lire avant le résultat : mode dégradé, injection de prompt."""
    if resultat["type"] == "confirmation":
        return  # le volet de résultat porte déjà l'alerte et la décision à prendre
    categories = _categories(resultat.get("types_injection", []))
    if categories and resultat["type"] == "caviardage":
        theme.alerte(
            "Traité malgré une injection de prompt suspectée",
            "Vous avez confirmé le traitement. Il est signalé dans l'historique : "
            "relisez attentivement le document caviardé avant de le diffuser.",
            categories,
        )
    elif categories:
        theme.alerte(
            "Injection de prompt suspectée",
            "Ce texte contient des consignes adressées au LLM. L'analyse a eu lieu, mais le caviardage "
            "vous demandera une confirmation et le résultat devra être relu.",
            categories,
        )
    if resultat.get("mode_degrade"):
        theme.alerte(
            "Mode dégradé : le LLM n'a pas répondu",
            "Seules les règles automatiques ont été appliquées (e-mails, téléphones, IBAN, "
            "n° de sécurité sociale, plaques). Les noms, prénoms, lieux, adresses, organisations "
            "et dates peuvent avoir échappé à la détection : relisez le document avant de le diffuser.",
        )


def _volet_confirmation(resultat: dict, perime: bool) -> None:
    """Volet de droite quand l'API a suspendu le caviardage pour injection de prompt."""
    _entete_volet("Document non traité", pastille="Texte modifié depuis ce contrôle" if perime else "")
    puces = "".join(f"<span>{html.escape(c)}</span>" for c in _categories(resultat["types_injection"]))
    st.html(
        '<div class="an-page bloque" role="alert">'
        "<strong>Injection de prompt suspectée</strong>"
        "<p>Ce texte contient des passages qui ressemblent à des consignes destinées au LLM. "
        "Par précaution, il n'a été ni caviardé ni archivé.</p>"
        f'<div class="an-categories">{puces}</div>'
        '<p style="margin-top:14px">Si le document est légitime (une citation, un exemple de sécurité…), '
        "vous pouvez le caviarder quand même. Le traitement sera signalé dans l'historique "
        "et le résultat devra être relu.</p></div>"
    )
    col_confirmer, col_annuler, _ = st.columns([1.5, 1, 1], gap="small")
    confirmer = col_confirmer.button(
        "Caviarder quand même",
        icon=":material/warning:",
        disabled=perime,
        width="stretch",
        help="Le texte a changé depuis ce contrôle : relancez le caviardage." if perime else None,
    )
    col_annuler.button("Annuler", type="tertiary", on_click=_annuler_confirmation, width="stretch")
    if confirmer:
        try:
            with st.spinner("Caviardage en cours, le LLM peut prendre quelques secondes…"):
                reponse = client.caviarder(resultat["contenu"], resultat["strategie"], confirmer=True)
        except ApiError as erreur:
            session.afficher_erreur_api(erreur)
        else:
            st.session_state["resultat"] = _resultat_caviardage(resultat["contenu"], resultat["strategie"], reponse)
            st.rerun()


def _resultat_caviardage(contenu: str, strategie: str, reponse: dict) -> dict:
    """Range la réponse de l'API dans l'état de la page."""
    commun = {
        "contenu": contenu,
        "strategie": strategie,
        "mode_degrade": reponse["mode_degrade"],
        "types_injection": reponse["types_injection"],
    }
    if reponse["confirmation_requise"]:
        return {"type": "confirmation", **commun}
    return {"type": "caviardage", "caviarde": reponse["caviarde"], **commun}


def _volet_resultat(resultat: dict | None, perime: bool) -> None:
    """Volet de droite : le texte analysé, le texte caviardé, ou la marche à suivre."""
    pastille = "Texte modifié depuis ce résultat" if perime else ""
    if resultat is None:
        _entete_volet("Résultat")
        st.html(surlignage.page_vide_html())
        return

    if resultat["type"] == "confirmation":
        _volet_confirmation(resultat, perime)
        return

    if resultat["type"] == "analyse":
        n = len(resultat["pii"])
        _entete_volet("Données détectées", _donnees(n) if n else "Aucune donnée", pastille)
        st.html(surlignage.texte_surligne_html(resultat["contenu"], resultat["pii"]))
        return

    paires = surlignage.liste_remplacements(resultat["contenu"], resultat["caviarde"])
    strategie = LIBELLES_STRATEGIES.get(resultat["strategie"], resultat["strategie"])
    _entete_volet("Document caviardé", f"{strategie} · {_pluriel(len(paires), 'remplacement')}", pastille)
    st.html(surlignage.texte_caviarde_html(resultat["contenu"], resultat["caviarde"]))
    st.download_button(
        "Télécharger le texte caviardé",
        data=resultat["caviarde"],
        file_name="document_caviarde.txt",
        mime="text/plain",
        icon=":material/download:",
        help="Fichier texte du document caviardé. Relisez-le avant de le diffuser.",
    )


def _detail(resultat: dict) -> None:
    """Sous les deux volets : la liste des détections ou des remplacements."""
    if resultat["type"] == "analyse":
        pii = resultat["pii"]
        st.html(f'<div class="an-volet"><h2>Détail des détections</h2><span class="an-meta">{_pluriel(len(pii), "ligne")}</span></div>')
        if not pii:
            st.caption("Aucune donnée personnelle n'a été détectée dans ce texte.")
            return
        st.html(surlignage.types_html(pii) + surlignage.tableau_pii_html(pii))
    else:
        paires = surlignage.liste_remplacements(resultat["contenu"], resultat["caviarde"])
        st.html(f'<div class="an-volet"><h2>Remplacements</h2><span class="an-meta">{_pluriel(len(paires), "ligne")}</span></div>')
        if not paires:
            st.caption("Aucune donnée personnelle détectée : le texte est inchangé.")
            return
        st.html(surlignage.tableau_remplacements_html(paires))
        with st.expander("Texte brut, à copier"):
            # st.code affiche le texte tel quel et fournit un bouton "copier" intégré
            st.code(resultat["caviarde"], language=None, wrap_lines=True)


# ----------------------------------------------------------------------
# Page
# ----------------------------------------------------------------------

def _guide() -> None:
    """Contenu du bouton « Comment ça marche » : la marche à suivre et la lecture des résultats."""
    st.html(
        '<div class="an-guide">'
        "<h3>Comment ça marche</h3>"
        "<ol>"
        "<li><b>Déposez le texte</b> dans le volet de gauche : collez-le, importez un fichier "
        ".txt ou .md, ou essayez avec l'exemple.</li>"
        "<li><b>Analysez</b> pour voir les données personnelles repérées, surlignées dans le texte, "
        "sans rien modifier.</li>"
        "<li><b>Choisissez une stratégie</b>, puis <b>caviardez</b> pour obtenir la version à diffuser.</li>"
        "<li><b>Relisez</b> le document caviardé, puis téléchargez-le ou copiez-le.</li>"
        "</ol>"
        "<h3>Lire le résultat</h3>"
        '<dl>'
        '<dt><span class="an-pii">Claire Martin<sup>Nom</sup></span></dt>'
        "<dd>Donnée repérée par l'analyse, avec son type.</dd>"
        '<dt><span class="an-masque">[EMAIL_1]</span></dt>'
        "<dd>Donnée masquée par un marqueur numéroté : une même valeur garde le même marqueur.</dd>"
        '<dt><span class="an-pseudo">Julie Bernard</span></dt>'
        "<dd>Donnée remplacée par une valeur fictive (pseudonymisation).</dd>"
        "</dl>"
        "<h3>Règles et LLM</h3>"
        "<p>Des règles repèrent les formats précis (e-mails, téléphones, IBAN, n° de sécurité sociale, "
        "plaques). Le LLM repère ce qui dépend du contexte : noms, lieux, adresses, organisations, dates. "
        "La colonne Confiance du détail indique sa certitude pour chaque donnée.</p>"
        "</div>"
    )


col_titre, col_aide = st.columns([4, 1.3], vertical_alignment="top", gap="small")
with col_titre:
    theme.entete(
        "Caviardage",
        "Anonymia s'appuie sur un LLM pour repérer les données personnelles : il en détecte la grande "
        "majorité, et une relecture avant diffusion apporte la touche finale. Le texte n'est pas "
        "conservé : seules des métadonnées sont archivées (empreinte du document, stratégie, "
        "nombre de données détectées).",
    )
with (
    col_aide.container(horizontal_alignment="right"),
    st.popover("Comment ça marche", icon=":material/help:", type="tertiary"),
):
    _guide()

# Les stratégies sont demandées à l'API une seule fois par session
if "strategies" not in st.session_state:
    try:
        st.session_state["strategies"] = client.strategies()
    except ApiError as erreur:
        session.afficher_erreur_api(erreur)
        st.stop()

# Barre d'outils : la stratégie à gauche, les actions à droite
st.space("small")
barre = st.container(key="barre")
col_strategie, col_vide, col_exemple, col_effacer, col_analyser, col_caviarder = barre.columns(
    [3.2, 1.2, 1, 0.8, 1, 1.1], vertical_alignment="bottom", gap="small"
)
with col_strategie:
    strategie = st.segmented_control(
        "Stratégie",
        st.session_state["strategies"],
        default=st.session_state["strategies"][0],
        format_func=lambda nom: LIBELLES_STRATEGIES.get(nom, nom),
        key="strategie",
        help="Utilisée au moment du caviardage. "
        + " ".join(AIDES_STRATEGIES.get(s, "") for s in st.session_state["strategies"]),
    ) or st.session_state["strategies"][0]
col_exemple.button(
    "Exemple",
    on_click=_inserer_exemple,
    type="tertiary",
    width="stretch",
    help="Remplit le volet de gauche avec un court texte fictif pour essayer l'application.",
)
col_effacer.button(
    "Effacer",
    on_click=_effacer,
    type="tertiary",
    width="stretch",
    help="Vide le texte, le fichier importé et le résultat.",
)
analyser_clique = col_analyser.button(
    "Analyser",
    width="stretch",
    icon=":material/search:",
    help="Repère les données personnelles et les surligne dans le texte, sans le modifier. "
    "Rien n'est archivé.",
)
caviarder_clique = col_caviarder.button(
    "Caviarder",
    type="primary",
    width="stretch",
    icon=":material/ink_eraser:",
    help="Remplace chaque donnée personnelle selon la stratégie choisie et produit le texte à diffuser.",
)
st.space("small")

contenu = st.session_state["contenu"]

if analyser_clique or caviarder_clique:
    if not contenu.strip():
        st.warning("Saisissez ou importez un texte avant de lancer le traitement.")
    else:
        try:
            if analyser_clique:
                with st.spinner("Analyse en cours, le LLM peut prendre quelques secondes…"):
                    reponse = client.analyser(contenu)
                st.session_state["resultat"] = {"type": "analyse", "contenu": contenu, **reponse}
            else:
                with st.spinner("Caviardage en cours, le LLM peut prendre quelques secondes…"):
                    reponse = client.caviarder(contenu, strategie)
                st.session_state["resultat"] = _resultat_caviardage(contenu, strategie, reponse)
        except ApiError as erreur:
            session.afficher_erreur_api(erreur)

resultat = st.session_state.get("resultat")
perime = bool(resultat) and resultat["contenu"] != contenu

if resultat:
    _bandeaux(resultat)
    st.space("small")

col_source, col_resultat = st.columns(2, gap="large")

with col_source:
    _entete_volet("Document source", f"{_nombre(len(contenu))} / {_nombre(MAX_CARACTERES)} caractères")
    st.text_area(
        "Texte à traiter",
        key="contenu",
        height=480,
        max_chars=MAX_CARACTERES,
        placeholder="Collez le texte ici, ou importez un fichier ci-dessous.",
        label_visibility="collapsed",
    )
    st.file_uploader(
        "Importer un fichier",
        type=["txt", "md"],
        key=f"fichier_{st.session_state['upload_n']}",
        on_change=_importer_fichier,
        label_visibility="collapsed",
        help="Le contenu du fichier remplace le texte du volet. Encodage UTF-8, 100 000 caractères au plus.",
    )
    if "erreur_import" in st.session_state:
        st.error(st.session_state["erreur_import"])

with col_resultat:
    _volet_resultat(resultat, perime)

if resultat and resultat["type"] != "confirmation":
    st.space("medium")
    _detail(resultat)
