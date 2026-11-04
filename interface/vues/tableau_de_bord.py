"""
Page Tableau de bord : vue de synthèse de l'activité (chiffres clés et répartitions).

Réservée aux superviseurs et aux administrateurs. Elle repose sur les mêmes données que la page
Historique (GET /journaux) : uniquement des métadonnées, jamais le texte des documents.
"""
from datetime import date

import journal
import session
import streamlit as st
from api_client import ApiClient, ApiError

utilisateur = session.exiger_connexion()

st.title("📊 Tableau de bord")

# Garde-fou d'affichage : la page n'est normalement pas proposée aux autres rôles,
# et l'API refuserait de toute façon la requête (erreur 403).
if utilisateur["role"] not in session.ROLES_HISTORIQUE:
    st.error("Le tableau de bord est réservé aux superviseurs et aux administrateurs.")
    st.stop()

client = ApiClient(utilisateur["token"])

try:
    nom_fuseau = st.context.timezone
except Exception:  # noqa: BLE001 - propriété absente selon la version de Streamlit
    nom_fuseau = None
tz = journal.fuseau(nom_fuseau)


def _logins() -> dict[int, str]:
    """Correspondance numéro -> login (lisible par un administrateur seulement, sinon vide)."""
    if utilisateur["role"] != "ADMIN":
        return {}
    try:
        return {u["id"]: u["login"] for u in client.utilisateurs()}
    except ApiError as erreur:
        if erreur.status_code == 401:
            session.afficher_erreur_api(erreur)  # session expirée : retour à la connexion
        return {}


def _charger(login: str, debut: date | None, fin: date | None) -> None:
    """Interroge l'API et range le résultat dans st.session_state (il survit aux relances du script)."""
    if debut and fin and debut > fin:
        st.warning("La date de début doit être antérieure ou égale à la date de fin.")
        return
    login = login.strip()
    try:
        with st.spinner("Chargement des données..."):
            traitements = client.journaux(login or None, debut, fin)
            logins = _logins()
    except ApiError as erreur:
        session.afficher_erreur_api(erreur)
        return
    st.session_state["tableau_de_bord"] = {
        "traitements": traitements,
        "logins": logins,
        "filtres": {"login": login, "debut": debut, "fin": fin},
    }


def _graphique(titre: str, repartition: dict[str, int], colonne: str) -> None:
    """Diagramme en barres d'une répartition {libellé: nombre}."""
    st.subheader(titre)
    st.bar_chart(
        [{colonne: nom, "Traitements": n} for nom, n in repartition.items()],
        x=colonne,
        y="Traitements",
        height=240,
    )


# Dans un formulaire, l'API n'est interrogée qu'au clic sur « Afficher »
with st.form("filtres_tableau_de_bord"):
    col_login, col_debut, col_fin = st.columns(3)
    login_filtre = col_login.text_input("Utilisateur (login)", placeholder="Tous les utilisateurs")
    debut_filtre = col_debut.date_input("Du", value=None, format="DD/MM/YYYY")
    fin_filtre = col_fin.date_input("Au", value=None, format="DD/MM/YYYY")
    recherche = st.form_submit_button("🔍 Afficher", type="primary")

if recherche:
    _charger(login_filtre, debut_filtre, fin_filtre)
elif "tableau_de_bord" not in st.session_state:
    _charger("", None, None)  # première visite : toute l'activité, sans filtre

resultat = st.session_state.get("tableau_de_bord")
if resultat is not None:
    traitements = resultat["traitements"]
    if not traitements:
        message = "Aucun traitement trouvé pour ces critères."
        if resultat["filtres"]["login"]:
            message += " Vérifiez l'orthographe du login : un login inconnu donne aussi une liste vide."
        st.info(message)
        st.stop()

    synthese = journal.tableau_de_bord(traitements, resultat["logins"], tz)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Traitements", synthese["traitements"])
    col2.metric("Données détectées", synthese["pii"])
    col3.metric("Moyenne par document", synthese["pii_moyenne"])
    col4.metric("Utilisateurs actifs", synthese["utilisateurs"])

    if synthese["sans_llm"]:
        st.warning(
            f"{synthese['sans_llm']} traitement(s) sur {synthese['traitements']} "
            f"({synthese['part_sans_llm']} %) ont été faits sans le LLM, avec les expressions "
            "régulières seules : service LLM indisponible, ou application lancée avec LLM_ENABLED=false."
        )

    if len(synthese["par_jour"]) > 1:
        st.subheader("Activité par jour")
        st.bar_chart(
            [{"Jour": jour, "Traitements": n} for jour, n in synthese["par_jour"].items()],
            x="Jour",
            y="Traitements",
            height=240,
        )

    gauche, droite = st.columns(2)
    with gauche:
        _graphique("Par utilisateur", synthese["par_utilisateur"], "Utilisateur")
        _graphique("Par stratégie", synthese["par_strategie"], "Stratégie")
    with droite:
        _graphique("Par détecteurs", synthese["par_detecteurs"], "Détecteurs")

    notes = [f"Jours comptés dans le fuseau {getattr(tz, 'key', 'UTC')}."]
    if not resultat["logins"]:
        notes.append("Utilisateurs affichés par numéro : seul un administrateur peut lire les logins.")
    st.caption(" ".join(notes))
