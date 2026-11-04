"""
Page Caviardage : saisir ou importer un texte, voir les données personnelles détectées,
puis obtenir le texte caviardé.

Mise en page : à gauche le document source, à droite le résultat (texte analysé ou
caviardé), et en dessous le détail des détections ou des remplacements.

Rappel Streamlit : le script est relancé à chaque clic. Ce qui doit survivre d'un clic
à l'autre (le texte, le dernier résultat) est donc rangé dans st.session_state.
"""
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


def _volet_resultat(resultat: dict | None, perime: bool) -> None:
    """Volet de droite : le texte analysé, le texte caviardé, ou la marche à suivre."""
    pastille = "Texte modifié depuis ce résultat" if perime else ""
    if resultat is None:
        _entete_volet("Résultat")
        st.html(surlignage.page_vide_html())
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

theme.entete(
    "Caviardage",
    "Le texte n'est pas conservé : seules des métadonnées sont archivées "
    "(empreinte du document, stratégie, nombre de données détectées).",
)

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
col_exemple.button("Exemple", on_click=_inserer_exemple, type="tertiary", width="stretch")
col_effacer.button("Effacer", on_click=_effacer, type="tertiary", width="stretch")
analyser_clique = col_analyser.button("Analyser", width="stretch", icon=":material/search:")
caviarder_clique = col_caviarder.button("Caviarder", type="primary", width="stretch", icon=":material/ink_eraser:")
st.space("small")

contenu = st.session_state["contenu"]

if analyser_clique or caviarder_clique:
    if not contenu.strip():
        st.warning("Saisissez ou importez un texte avant de lancer le traitement.")
    else:
        try:
            if analyser_clique:
                with st.spinner("Analyse en cours, le LLM peut prendre quelques secondes…"):
                    pii = client.analyser(contenu)
                st.session_state["resultat"] = {"type": "analyse", "contenu": contenu, "pii": pii}
            else:
                with st.spinner("Caviardage en cours, le LLM peut prendre quelques secondes…"):
                    caviarde = client.caviarder(contenu, strategie)
                st.session_state["resultat"] = {
                    "type": "caviardage",
                    "contenu": contenu,
                    "strategie": strategie,
                    "caviarde": caviarde,
                }
        except ApiError as erreur:
            session.afficher_erreur_api(erreur)

resultat = st.session_state.get("resultat")
perime = bool(resultat) and resultat["contenu"] != contenu

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
    )
    if "erreur_import" in st.session_state:
        st.error(st.session_state["erreur_import"])

with col_resultat:
    _volet_resultat(resultat, perime)

if resultat:
    st.space("medium")
    _detail(resultat)
