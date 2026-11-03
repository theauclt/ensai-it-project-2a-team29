"""Page de connexion : demande l'identifiant et le mot de passe, puis appelle l'API."""
import session
import streamlit as st
from api_client import ApiClient, ApiError

st.title("🔒 Anonymia")
st.caption("Détection et caviardage de données personnelles")

# Message laissé par session.courante() quand la session a expiré
message = st.session_state.pop("message_connexion", None)
if message:
    st.info(message)

# Un formulaire regroupe les champs : le script ne se relance qu'au clic sur le bouton
# (et non à chaque caractère tapé).
with st.form("formulaire_connexion"):
    login = st.text_input("Identifiant")
    mot_de_passe = st.text_input("Mot de passe", type="password")
    envoye = st.form_submit_button("Se connecter")

if envoye:
    if not login or not mot_de_passe:
        st.error("Renseignez l'identifiant et le mot de passe.")
    else:
        try:
            with st.spinner("Connexion en cours..."):
                token = ApiClient().connexion(login, mot_de_passe)
            session.ouvrir(token)
        except (ApiError, ValueError) as erreur:
            st.error(str(erreur))
        else:
            # On relance le script : app.py voit maintenant un utilisateur connecté
            # et affiche les pages qui lui sont destinées.
            st.rerun()
