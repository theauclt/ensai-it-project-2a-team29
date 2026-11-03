"""Page d'accueil affichée après la connexion (provisoire : elle sera enrichie ensuite)."""
import session
import streamlit as st

utilisateur = session.exiger_connexion()

st.title("🏠 Accueil")
st.success(f"Bonjour {utilisateur['login']} ! Rôle : {utilisateur['role']}.")
st.write(
    "La connexion à l'API fonctionne. Les écrans de caviardage, d'historique "
    "et d'administration seront ajoutés aux étapes suivantes."
)
