"""
Page Historique : liste des traitements archivés, avec filtres, totaux et export CSV.

Réservée aux superviseurs et aux administrateurs. L'historique ne contient que des
métadonnées (date, utilisateur, stratégie, nombre de données détectées, empreinte du
document) : jamais le texte des documents ni les données personnelles elles-mêmes.
"""
from datetime import date

import journal
import session
import streamlit as st
from api_client import ApiClient, ApiError

utilisateur = session.exiger_connexion()

st.title("📜 Historique")

# Garde-fou d'affichage : la page n'est normalement pas proposée aux autres rôles,
# et l'API refuserait de toute façon la requête (erreur 403).
if utilisateur["role"] not in session.ROLES_HISTORIQUE:
    st.error("L'historique est réservé aux superviseurs et aux administrateurs.")
    st.stop()

client = ApiClient(utilisateur["token"])

# Fuseau du navigateur si Streamlit le fournit (versions récentes), sinon Paris
try:
    nom_fuseau = st.context.timezone
except Exception:  # noqa: BLE001 - propriété absente selon la version de Streamlit
    nom_fuseau = None
tz = journal.fuseau(nom_fuseau)


def _logins() -> dict[int, str]:
    """
    Correspondance numéro -> login, que seul un administrateur peut lire.

    Pour un superviseur, ou si la demande échoue, on renvoie un dictionnaire vide :
    les utilisateurs sont alors affichés par leur numéro.
    """
    if utilisateur["role"] != "ADMIN":
        return {}
    try:
        return {u["id"]: u["login"] for u in client.utilisateurs()}
    except ApiError as erreur:
        if erreur.status_code == 401:
            session.afficher_erreur_api(erreur)  # session expirée : retour à la connexion
        return {}


def _description_filtres(filtres: dict) -> str:
    """Phrase qui rappelle les critères utilisés pour la liste affichée."""
    morceaux = []
    if filtres["login"]:
        morceaux.append(f"utilisateur « {filtres['login']} »")
    if filtres["debut"]:
        morceaux.append(f"à partir du {filtres['debut'].strftime('%d/%m/%Y')}")
    if filtres["fin"]:
        morceaux.append(f"jusqu'au {filtres['fin'].strftime('%d/%m/%Y')}")
    return "Filtres appliqués : " + (", ".join(morceaux) if morceaux else "aucun (tous les traitements)")


def _charger(login: str, debut: date | None, fin: date | None) -> None:
    """Interroge l'API et range le résultat dans st.session_state (il survit aux relances du script)."""
    if debut and fin and debut > fin:
        st.warning("La date de début doit être antérieure ou égale à la date de fin.")
        return
    login = login.strip()
    try:
        with st.spinner("Chargement de l'historique..."):
            traitements = client.journaux(login or None, debut, fin)
            logins = _logins()
    except ApiError as erreur:
        session.afficher_erreur_api(erreur)
        return
    st.session_state["historique"] = {
        "traitements": traitements,
        "logins": logins,
        "filtres": {"login": login, "debut": debut, "fin": fin},
    }


# ----------------------------------------------------------------------
# Filtres. Dans un formulaire, l'API n'est interrogée qu'au clic sur « Rechercher »
# et non à chaque caractère tapé.
# ----------------------------------------------------------------------

with st.form("filtres_historique"):
    col_login, col_debut, col_fin = st.columns(3)
    login_filtre = col_login.text_input("Utilisateur (login)", placeholder="Tous les utilisateurs")
    debut_filtre = col_debut.date_input("Du", value=None, format="DD/MM/YYYY")
    fin_filtre = col_fin.date_input("Au", value=None, format="DD/MM/YYYY")
    recherche = st.form_submit_button("🔍 Rechercher", type="primary")

if recherche:
    _charger(login_filtre, debut_filtre, fin_filtre)
elif "historique" not in st.session_state:
    # Première visite : on affiche directement les traitements récents, sans filtre
    _charger("", None, None)

# ----------------------------------------------------------------------
# Résultat
# ----------------------------------------------------------------------

resultat = st.session_state.get("historique")
if resultat is not None:
    traitements = resultat["traitements"]
    st.caption(_description_filtres(resultat["filtres"]))

    if not traitements:
        message = "Aucun traitement trouvé pour ces critères."
        if resultat["filtres"]["login"]:
            message += " Vérifiez l'orthographe du login : un login inconnu donne aussi une liste vide."
        st.info(message)
    else:
        stats = journal.statistiques(traitements, tz)
        col1, col2, col3 = st.columns(3)
        col1.metric("Traitements", stats["traitements"])
        col2.metric("Données détectées", stats["pii"])
        col3.metric("Utilisateurs", stats["utilisateurs"])

        if len(stats["par_jour"]) > 1:
            st.bar_chart(
                [{"Jour": jour, "Traitements": n} for jour, n in stats["par_jour"].items()],
                x="Jour",
                y="Traitements",
                height=220,
            )

        st.dataframe(
            journal.lignes_tableau(traitements, resultat["logins"], tz),
            hide_index=True,
            column_config={
                "Date": st.column_config.DatetimeColumn("Date", format="DD/MM/YYYY HH:mm:ss"),
                "Données détectées": st.column_config.NumberColumn("Données détectées", format="%d"),
            },
        )

        # Le CSV contient les empreintes complètes (le tableau les raccourcit)
        st.download_button(
            "⬇️ Exporter en CSV",
            data=journal.vers_csv(
                journal.lignes_tableau(traitements, resultat["logins"], tz, hash_complet=True)
            ),
            file_name=f"historique_{date.today().isoformat()}.csv",
            mime="text/csv",
        )

        notes = [f"Heures affichées en {getattr(tz, 'key', 'UTC')}."]
        notes.append("Les filtres « Du » et « Au » comptent des jours UTC.")
        if not resultat["logins"]:
            notes.append(
                "Les utilisateurs sont affichés par numéro : seul un administrateur peut associer "
                "un numéro à un login. Le filtre, lui, accepte un login."
            )
        st.caption(" ".join(notes))
