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
page_accueil = st.Page("vues/accueil.py", title="Accueil", icon="🏠", default=True)

utilisateur = session.courante()

if utilisateur is None:
    pages = [page_connexion]
else:
    # Les pages Caviardage, Historique et Administration seront ajoutées ici
    # aux étapes suivantes, chacune réservée aux rôles concernés.
    pages = [page_accueil]

    with st.sidebar:
        st.caption(f"Connecté : **{utilisateur['login']}** ({utilisateur['role']})")
        if st.button("Se déconnecter"):
            session.deconnecter()
            st.rerun()

st.navigation(pages).run()
