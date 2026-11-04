"""
Page Tableau de bord : vue de synthèse de l'activité (chiffres clés et répartitions).

Réservée aux superviseurs et aux administrateurs. Elle repose sur les mêmes données que la page
Historique (GET /journaux) : uniquement des métadonnées, jamais le texte des documents.
"""
from datetime import date

import graphiques
import journal
import session
import streamlit as st
from api_client import ApiClient, ApiError

utilisateur = session.exiger_connexion()

st.title("Tableau de bord")

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

    # ----- Chiffres clés -----
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Traitements", synthese["traitements"], help="Nombre de documents caviardés sur la période.")
    col2.metric(
        "Données détectées",
        synthese["pii"],
        help="Total des données personnelles trouvées (noms, e-mails, téléphones...) dans tous les documents.",
    )
    col3.metric(
        "Moyenne par document",
        synthese["pii_moyenne"],
        help="Données détectées ÷ traitements. Exemple : 28 données dans 7 documents = 4,0 par document. "
        "Elle indique à quel point les documents traités sont riches en données personnelles.",
    )
    col4.metric(
        "Maximum sur un document",
        synthese["pii_max"],
        help="Le plus grand nombre de données détectées dans un seul document.",
    )
    col5.metric(
        "Utilisateurs actifs",
        synthese["utilisateurs"],
        help="Nombre de comptes ayant fait au moins un traitement sur la période.",
    )

    if synthese["sans_llm"]:
        st.warning(
            f"{synthese['sans_llm']} traitement(s) sur {synthese['traitements']} "
            f"({synthese['part_sans_llm']} %) ont été faits sans le LLM, avec les expressions "
            "régulières seules : service LLM indisponible, ou application lancée avec LLM_ENABLED=false. "
            "Les noms, lieux et dates de naissance peuvent alors ne pas avoir été détectés."
        )

    # ----- Juge d'injection LLM -----
    juge = synthese["juge"]
    if juge["detected"] or juge["not_detected"] or juge["unavailable"]:
        st.subheader("Juge d'injection LLM")
        col_a, col_b, col_c = st.columns(3)
        col_a.metric("Injections repérées", juge["detected"], help="Traitements où le juge a repéré une tentative de manipulation.")
        col_b.metric(
            "Rien repéré",
            juge["not_detected"],
            help="Le juge n'a rien repéré. Cela ne prouve pas que les documents sont sûrs : un document peut tromper le juge.",
        )
        col_c.metric("Juge indisponible", juge["unavailable"], help="Le juge n'a pas pu répondre. Le caviardage n'est pas affecté.")
        if juge["detected"]:
            st.warning(
                f"{juge['detected']} traitement(s) ont été signalés par le juge comme des tentatives de manipulation. "
                "Consultez l'historique (colonne « Juge LLM »)."
            )

    # ----- Activité -----
    if len(synthese["par_jour"]) > 1:
        st.subheader("Activité par jour")
        jours = {date.fromisoformat(jour).strftime("%d/%m"): n for jour, n in synthese["par_jour"].items()}
        st.altair_chart(graphiques.barres_verticales(jours, "Jour"), use_container_width=True)

    gauche, droite = st.columns(2)
    with gauche:
        st.subheader("Par utilisateur")
        st.altair_chart(graphiques.barres_horizontales(synthese["par_utilisateur"], "Utilisateur"), use_container_width=True)
    with droite:
        st.subheader("Données détectées par document")
        st.caption("Combien de documents contiennent peu ou beaucoup de données personnelles.")
        st.altair_chart(
            graphiques.barres_verticales(synthese["par_tranche"], "Données par document", graphiques.COULEUR_ALERTE),
            use_container_width=True,
        )

    st.subheader("Données détectées par type")
    if synthese["par_type"]:
        st.altair_chart(
            graphiques.barres_horizontales(synthese["par_type"], "Type de donnée", "Données"),
            use_container_width=True,
        )
    else:
        st.info("Aucun type de donnée enregistré sur cette période.")
    if synthese["traitements_sans_types"]:
        st.caption(
            f"{synthese['traitements_sans_types']} traitement(s) plus ancien(s) n'ont pas de détail par type "
            "et ne sont pas comptés dans ce graphique."
        )

    gauche, droite = st.columns(2)
    with gauche:
        st.subheader("Stratégie choisie")
        st.altair_chart(graphiques.anneau(synthese["par_strategie"], "Stratégie"), use_container_width=True)
    with droite:
        st.subheader("Détecteurs utilisés")
        st.altair_chart(graphiques.anneau(synthese["par_detecteurs"], "Détecteurs"), use_container_width=True)

    # ----- Détail -----
    st.subheader("Détail par utilisateur")
    st.dataframe(
        synthese["detail_utilisateurs"],
        hide_index=True,
        use_container_width=True,
        column_config={
            "Dernier traitement": st.column_config.DatetimeColumn("Dernier traitement", format="DD/MM/YYYY HH:mm"),
        },
    )

    with st.expander("Comment lire ces chiffres ?"):
        st.markdown(
            "- **Moyenne par document** : données détectées ÷ traitements. Une moyenne de 4,0 signifie qu'un "
            "document contient en général 4 données personnelles.\n"
            "- **Données détectées par document** : répartition des documents selon le nombre de données "
            "trouvées. Une moyenne seule peut cacher un seul document très chargé : ce graphique le montre.\n"
            "- **Détecteurs** : « Regex + LLM » est le fonctionnement normal ; « Regex seul » signale un "
            "traitement sans le LLM.\n"
            "- Ces chiffres viennent de l'historique : ils ne contiennent jamais le texte des documents."
        )

    notes = [f"Jours comptés dans le fuseau {getattr(tz, 'key', 'UTC')}."]
    if not resultat["logins"]:
        notes.append("Utilisateurs affichés par numéro : seul un administrateur peut lire les logins.")
    st.caption(" ".join(notes))
