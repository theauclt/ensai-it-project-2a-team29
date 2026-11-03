"""
Page Caviardage : saisir ou importer un texte, voir les données personnelles détectées
(surlignées par type), puis obtenir le texte caviardé.

Rappel Streamlit : le script est relancé à chaque clic. Ce qui doit survivre d'un clic
à l'autre (le texte, le dernier résultat) est donc rangé dans st.session_state.
"""
import session
import streamlit as st
import surlignage
from api_client import ApiClient, ApiError

MAX_CARACTERES = 100_000  # limite de l'API pour un document

LIBELLES_STRATEGIES = {
    "masking": "Masquage : remplace par des marqueurs ([EMAIL_1], [NOM_2]...)",
    "pseudonymization": "Pseudonymisation : remplace par des valeurs fictives",
}

EXEMPLE = (
    "Bonjour, je m'appelle Claire Martin, née le 23 septembre 1984 à Nantes.\n"
    "Vous pouvez me joindre à claire.martin@example.com ou au 06 12 34 56 78.\n"
    "Mon IBAN : FR1420041010050500013M02606."
)

utilisateur = session.exiger_connexion()
client = ApiClient(utilisateur["token"])

st.session_state.setdefault("contenu", "")
st.session_state.setdefault("upload_n", 0)  # change pour vider le sélecteur de fichier


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
            f"Le fichier fait {len(texte):,} caractères ; la limite est de {MAX_CARACTERES:,}.".replace(",", " ")
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
# Affichage des résultats
# ----------------------------------------------------------------------

def _afficher_analyse(resultat: dict) -> None:
    pii = resultat["pii"]
    if not pii:
        st.success("Aucune donnée personnelle détectée dans ce texte.")
        return

    pluriel = "s" if len(pii) > 1 else ""
    st.subheader(f"{len(pii)} donnée{pluriel} personnelle{pluriel} détectée{pluriel}")
    st.html(surlignage.legende_html(pii))
    st.html(surlignage.texte_surligne_html(resultat["contenu"], pii))

    with st.expander("Détail des détections"):
        st.dataframe(
            [
                {
                    "Texte": p["texte"],
                    "Type": surlignage.libelle(p["type"]),
                    "Détecteur": p["detecteur"],
                    "Début": p["debut"],
                    "Fin": p["fin"],
                }
                for p in pii
            ],
            hide_index=True,
        )


def _afficher_caviardage(resultat: dict) -> None:
    st.subheader("Document caviardé")
    st.caption(f"Stratégie : {LIBELLES_STRATEGIES.get(resultat['strategie'], resultat['strategie'])}")
    if resultat["caviarde"] == resultat["contenu"]:
        st.info("Aucune donnée personnelle détectée : le texte est inchangé.")
    # st.code affiche le texte tel quel et fournit un bouton "copier" intégré
    st.code(resultat["caviarde"], language=None, wrap_lines=True)
    st.download_button(
        "Télécharger (.txt)",
        data=resultat["caviarde"],
        file_name="document_caviarde.txt",
        mime="text/plain",
    )


# ----------------------------------------------------------------------
# Page
# ----------------------------------------------------------------------

st.title("✂️ Caviardage")
st.caption(
    "Le texte n'est pas conservé : lors d'un caviardage, seules des métadonnées "
    "(empreinte du document, stratégie, nombre de données détectées) sont archivées."
)

# Les stratégies sont demandées à l'API une seule fois par session
if "strategies" not in st.session_state:
    try:
        st.session_state["strategies"] = client.strategies()
    except ApiError as erreur:
        session.afficher_erreur_api(erreur)
        st.stop()

st.file_uploader(
    "Importer un fichier texte (.txt ou .md)",
    type=["txt", "md"],
    key=f"fichier_{st.session_state['upload_n']}",
    on_change=_importer_fichier,
)
if "erreur_import" in st.session_state:
    st.error(st.session_state["erreur_import"])

st.text_area(
    "Texte à traiter",
    key="contenu",
    height=260,
    max_chars=MAX_CARACTERES,
    placeholder="Saisissez, collez ou importez un texte...",
)
contenu = st.session_state["contenu"]

strategie = st.selectbox(
    "Stratégie de caviardage",
    st.session_state["strategies"],
    format_func=lambda nom: LIBELLES_STRATEGIES.get(nom, nom),
)

col_analyser, col_caviarder, col_exemple, col_effacer = st.columns(4)
analyser_clique = col_analyser.button("🔍 Analyser")
caviarder_clique = col_caviarder.button("✂️ Caviarder", type="primary")
col_exemple.button("Insérer un exemple", on_click=_inserer_exemple)
col_effacer.button("Effacer", on_click=_effacer)

if analyser_clique or caviarder_clique:
    if not contenu.strip():
        st.warning("Saisissez ou importez un texte avant de lancer le traitement.")
    else:
        try:
            if analyser_clique:
                with st.spinner("Analyse en cours (cela peut prendre quelques secondes avec le LLM)..."):
                    pii = client.analyser(contenu)
                st.session_state["resultat"] = {"type": "analyse", "contenu": contenu, "pii": pii}
            else:
                with st.spinner("Caviardage en cours (cela peut prendre quelques secondes avec le LLM)..."):
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
if resultat:
    st.divider()
    if resultat["contenu"] != contenu:
        st.info("Le texte a été modifié depuis ce résultat : relancez le traitement pour le mettre à jour.")
    if resultat["type"] == "analyse":
        _afficher_analyse(resultat)
    else:
        _afficher_caviardage(resultat)
