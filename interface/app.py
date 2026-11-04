"""
Point d'entrée de l'interface Anonymia.

Lancement (depuis la racine du dépôt, API déjà lancée) :
    streamlit run interface/app.py

Ce fichier est le "cadre" de l'application : il s'exécute à chaque clic, décide
quelles pages afficher selon l'utilisateur connecté, puis lance la page choisie.
"""
import session
import streamlit as st
import theme

# Doit être le tout premier appel Streamlit du script
st.set_page_config(page_title="Anonymia", page_icon=":material/description:", layout="wide")
theme.appliquer()

# Les chemins des pages sont relatifs à ce fichier
page_connexion = st.Page("vues/connexion.py", title="Connexion", icon=":material/login:")
page_caviardage = st.Page("vues/caviardage.py", title="Caviardage", icon=":material/ink_eraser:", default=True)
page_tableau_de_bord = st.Page("vues/tableau_de_bord.py", title="Tableau de bord", icon=":material/monitoring:")
page_historique = st.Page("vues/historique.py", title="Historique", icon=":material/history:")
page_administration = st.Page("vues/administration.py", title="Administration", icon=":material/group:")

utilisateur = session.courante()

if utilisateur is None:
    pages = [page_connexion]
else:
    # Page ouverte à tous les utilisateurs connectés
    pages = [page_caviardage]
    # Pages réservées à certains rôles (l'API contrôle aussi les droits : ici, c'est de l'affichage)
    suivi = []
    if utilisateur["role"] in session.ROLES_HISTORIQUE:
        suivi += [page_tableau_de_bord, page_historique]
    if utilisateur["role"] in session.ROLES_ADMINISTRATION:
        suivi.append(page_administration)
    pages += suivi

    # Barre latérale dessinée par l'application (le menu automatique de Streamlit est masqué)
    with st.sidebar:
        theme.produit()
        st.page_link(page_caviardage)
        if suivi:
            st.html('<div class="an-groupe">Suivi</div>')
            for page in suivi:
                st.page_link(page)
        theme.compte(utilisateur["login"], utilisateur["role"])
        if st.button("Se déconnecter", type="tertiary", icon=":material/logout:"):
            session.deconnecter()
            st.rerun()

st.navigation(pages, position="hidden").run()
