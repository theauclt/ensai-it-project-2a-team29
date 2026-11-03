"""
Point d'entrée de l'interface Anonymia.

Lancement (depuis la racine du dépôt, API déjà lancée) :
    streamlit run interface/app.py

Ce fichier est le "cadre" de l'application : il s'exécute à chaque clic, décide
quelles pages afficher selon l'utilisateur connecté, puis lance la page choisie.
"""
import session
import streamlit as st

# Doit être le tout premier appel Streamlit du script
st.set_page_config(page_title="Anonymia", page_icon="🔒", layout="wide")

# Les chemins des pages sont relatifs à ce fichier
page_connexion = st.Page("vues/connexion.py", title="Connexion", icon="🔑")
page_caviardage = st.Page("vues/caviardage.py", title="Caviardage", icon="✂️", default=True)
page_historique = st.Page("vues/historique.py", title="Historique", icon="📜")

utilisateur = session.courante()

if utilisateur is None:
    pages = [page_connexion]
else:
    # Page ouverte à tous les utilisateurs connectés
    pages = [page_caviardage]
    # Pages réservées à certains rôles (l'API contrôle aussi les droits : ici, c'est de l'affichage)
    if utilisateur["role"] in session.ROLES_HISTORIQUE:
        pages.append(page_historique)
    # La page Administration sera ajoutée ici à l'étape suivante, pour les ADMIN

    with st.sidebar:
        st.caption(f"Connecté : **{utilisateur['login']}** ({utilisateur['role']})")
        if st.button("Se déconnecter"):
            session.deconnecter()
            st.rerun()

st.navigation(pages).run()
