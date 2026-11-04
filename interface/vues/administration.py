"""
Page Administration : gestion des comptes (liste, création, rôle, activation, suppression).

Réservée aux administrateurs. Les règles de protection (ne pas se retirer son propre rôle, garder
au moins un administrateur actif...) sont appliquées par l'API : la page se contente de désactiver
les boutons évidents et d'afficher le message de l'API si elle refuse une opération.
"""
import comptes
import journal
import session
import streamlit as st
from api_client import ApiClient, ApiError

utilisateur = session.exiger_connexion()

st.title("Administration")

# Garde-fou d'affichage : la page n'est normalement pas proposée aux autres rôles,
# et l'API refuserait de toute façon chaque requête (erreur 403).
if utilisateur["role"] not in session.ROLES_ADMINISTRATION:
    st.error("La gestion des comptes est réservée aux administrateurs.")
    st.stop()

client = ApiClient(utilisateur["token"])

try:
    nom_fuseau = st.context.timezone
except Exception:  # noqa: BLE001 - propriété absente selon la version de Streamlit
    nom_fuseau = None
tz = journal.fuseau(nom_fuseau)


def _charger_comptes() -> None:
    """Relit la liste des comptes auprès de l'API (en cas d'erreur, affiche le message et arrête la page)."""
    try:
        st.session_state["comptes"] = client.utilisateurs()
    except ApiError as erreur:
        session.afficher_erreur_api(erreur)  # sur un 401 : retour à la connexion
        st.stop()


def _terminer(type_message: str, texte: str) -> None:
    """Mémorise un message (affiché après la relance), recharge la liste et relance la page."""
    st.session_state["message_admin"] = (type_message, texte)
    _charger_comptes()
    st.rerun()


def _appliquer(action, succes: str) -> None:
    """Exécute une opération de l'API, puis affiche son résultat (succès ou message d'erreur de l'API)."""
    try:
        action()
    except ApiError as erreur:
        if erreur.status_code == 401:
            session.afficher_erreur_api(erreur)
        _terminer("error", str(erreur))
    _terminer("success", succes)


if "comptes" not in st.session_state:
    _charger_comptes()

# Message laissé par l'action précédente
message = st.session_state.pop("message_admin", None)
if message:
    getattr(st, message[0])(message[1])

liste = st.session_state["comptes"]
par_id = {c["id"]: c for c in liste}

onglet_comptes, onglet_creation = st.tabs(["Comptes", "Créer un compte"])

# ----------------------------------------------------------------------
# Onglet 1 : liste et modification des comptes
# ----------------------------------------------------------------------
with onglet_comptes:
    st.caption(comptes.resume(liste))
    st.dataframe(comptes.lignes_tableau(liste, tz, utilisateur["login"]), hide_index=True)
    if st.button("🔄 Actualiser la liste"):
        _terminer("info", "Liste actualisée.")

    st.divider()
    st.subheader("Modifier un compte")

    # Si le compte choisi a disparu (supprimé, ou par un autre administrateur), on repart de zéro
    if st.session_state.get("compte_choisi") not in par_id:
        st.session_state.pop("compte_choisi", None)

    choix = st.selectbox(
        "Compte",
        [c["id"] for c in comptes.trier(liste)],
        format_func=lambda i: comptes.libelle_compte(par_id[i]),
        key="compte_choisi",
    )
    cible = par_id[choix]
    c_est_moi = cible["login"] == utilisateur["login"]

    if c_est_moi:
        st.info(
            "C'est votre compte : vous ne pouvez ni changer votre rôle, ni le désactiver, ni le supprimer. "
            "Demandez à un autre administrateur si besoin."
        )

    # --- Rôle ---
    role_actuel = cible["role"]
    nouveau_role = st.selectbox(
        "Rôle",
        comptes.ROLES,
        index=comptes.ROLES.index(role_actuel) if role_actuel in comptes.ROLES else 0,
        format_func=comptes.libelle_role,
        key=f"role_{cible['id']}",
        disabled=c_est_moi,
    )
    if st.button(
        "Appliquer le rôle",
        key=f"appliquer_role_{cible['id']}",
        disabled=c_est_moi or nouveau_role == role_actuel,
    ):
        _appliquer(
            lambda: client.changer_role(cible["id"], nouveau_role),
            f"Rôle de « {cible['login']} » : {comptes.libelle_role(nouveau_role)}.",
        )

    # --- Activation ---
    if cible["est_active"]:
        if st.button("Désactiver le compte", key=f"desactiver_{cible['id']}", disabled=c_est_moi):
            _appliquer(
                lambda: client.definir_activation(cible["id"], False),
                f"Compte « {cible['login']} » désactivé.",
            )
        st.caption("Un compte désactivé ne peut plus se connecter. Ses traitements restent dans l'historique.")
    else:
        if st.button("Réactiver le compte", key=f"reactiver_{cible['id']}"):
            _appliquer(
                lambda: client.definir_activation(cible["id"], True),
                f"Compte « {cible['login']} » réactivé.",
            )

    st.caption(
        "Un changement de rôle ou une désactivation s'applique à la prochaine connexion de la personne : "
        "sa session en cours reste valable jusqu'à 30 minutes."
    )

    # --- Suppression (définitive : confirmation en tapant l'identifiant) ---
    if not c_est_moi:
        with st.expander("🗑️ Supprimer ce compte (irréversible)"):
            st.warning(
                "La suppression efface aussi tous les traitements archivés de ce compte, "
                "donc une partie de l'historique. Préférez la désactivation."
            )
            with st.form(f"suppression_{cible['id']}"):
                saisie = st.text_input(f"Pour confirmer, tapez l'identifiant : {cible['login']}")
                supprimer = st.form_submit_button("Supprimer définitivement")
            if supprimer:
                if not comptes.suppression_confirmee(saisie, cible["login"]):
                    st.error("L'identifiant saisi ne correspond pas : rien n'a été supprimé.")
                else:
                    st.session_state.pop("compte_choisi", None)
                    _appliquer(
                        lambda: client.supprimer_utilisateur(cible["id"]),
                        f"Compte « {cible['login']} » supprimé.",
                    )

# ----------------------------------------------------------------------
# Onglet 2 : création d'un compte
# ----------------------------------------------------------------------
with onglet_creation:
    # Le numéro change après chaque création réussie : le formulaire repart alors vide
    n = st.session_state.setdefault("creation_n", 0)
    with st.form(f"creation_{n}"):
        login = st.text_input("Identifiant", key=f"nouveau_login_{n}")
        mot_de_passe = st.text_input(
            f"Mot de passe ({comptes.MOT_DE_PASSE_MIN} caractères minimum)",
            type="password",
            autocomplete="new-password",
            key=f"nouveau_mdp_{n}",
        )
        confirmation = st.text_input(
            "Confirmer le mot de passe",
            type="password",
            autocomplete="new-password",
            key=f"nouveau_confirmation_{n}",
        )
        role = st.selectbox("Rôle", comptes.ROLES, format_func=comptes.libelle_role, key=f"nouveau_role_{n}")
        cree = st.form_submit_button("Créer le compte", type="primary")

    if cree:
        erreur = comptes.verifier_creation(login, mot_de_passe, confirmation)
        if erreur:
            st.error(erreur)
        else:
            try:
                client.creer_utilisateur(login.strip(), mot_de_passe, role)
            except ApiError as erreur_api:
                if erreur_api.status_code == 401:
                    session.afficher_erreur_api(erreur_api)
                st.error(str(erreur_api))
            else:
                st.session_state["creation_n"] = n + 1
                _terminer("success", f"Compte « {login.strip()} » créé avec le rôle {comptes.libelle_role(role)}.")
