"""
Habillage visuel de l'interface Anonymia.

Les couleurs de base et les polices sont dans .streamlit/config.toml. Ce module ajoute
ce que le thème Streamlit ne sait pas faire : le cadre gris pierre autour d'une feuille
blanche, la barre latérale de l'application et les styles du document caviardé.

Il n'affiche aucune donnée venant de l'utilisateur sans l'échapper (voir html.escape).
"""
import html
import re

import streamlit as st

# Marque d'Anonymia : une feuille dont une ligne est caviardée.
# Marque d'Anonymia : une feuille dont une ligne est caviardée. Dessinée en HTML et CSS
# (st.html retire les balises <svg>).
MARQUE_SVG = (
    '<span class="an-marque" aria-hidden="true"><i class="l"></i><i class="c"></i><i class="l court"></i></span>'
)

LIBELLES_ROLES = {
    "USER": "Agent",
    "SUPERVISOR": "Superviseur",
    "ADMIN": "Administrateur",
}

_CSS = """
<style>
:root {
  --an-frame: #f4f4f1;
  --an-sheet: #ffffff;
  --an-raised: #f4f5f6;
  --an-active: #e8e8e4;
  --an-border: #e3e4e6;
  --an-rule: #eeeff0;
  --an-control: #cdced1;
  --an-ink: #131416;
  --an-muted: #5d5f60;
  --an-accent: #1b6c80;
  --an-accent-pale: #e3eff2;
  --an-warning-bg: #fffbeb;
  --an-warning-ink: #92400e;
  --an-radius-sheet: 16px;
  --an-radius-card: 8px;
  --an-radius-control: 6px;
}

/* ---------- Le cadre et la feuille ---------- */
[data-testid="stApp"], [data-testid="stAppViewContainer"] { background: var(--an-frame); }
header[data-testid="stHeader"] { background: var(--an-frame); height: 48px; }
[data-testid="stMain"] { padding: 48px 8px 0 0; background: var(--an-frame); }
[data-testid="stMainBlockContainer"] {
  background: var(--an-sheet);
  border: 1px solid var(--an-border);
  border-radius: var(--an-radius-sheet);
  padding: 28px 32px 40px;
  max-width: none;
  flex: 0 0 auto;
  height: auto;
  min-height: calc(100vh - 56px);
  margin-bottom: 8px;
}
[data-testid="stSidebar"] { border-right: none; }
[data-testid="stSidebar"] > div:first-child { background: var(--an-frame); }
[data-testid="stSidebarHeader"] { height: 48px; padding-bottom: 0; margin-bottom: 0; }
[data-testid="stSidebarUserContent"] { padding-top: 0; }
[data-testid="stDecoration"] { display: none; }

/* Pas de titre en majuscules espacées, pas d'ancre au survol des titres */
[data-testid="stHeaderActionElements"] { display: none; }
h1, h2, h3 { letter-spacing: -0.01em; }
h1 { padding: 0 !important; }

/* Chiffres alignés partout où ils servent à comparer */
.an-num, table td, table th { font-variant-numeric: tabular-nums; }

/* ---------- Barre latérale ---------- */
.an-marque {
  flex: none; box-sizing: border-box; width: 22px; height: 28px; border: 1.5px solid var(--an-ink); border-radius: 3px;
  background: #ffffff; display: flex; flex-direction: column; justify-content: center; gap: 3px; padding: 0 3.5px;
}
.an-marque i { display: block; height: 1.5px; border-radius: 1px; background: #9a9c9e; }
.an-marque i.c { height: 4.5px; background: var(--an-ink); }
.an-marque i.court { width: 60%; }
.an-produit { display: flex; align-items: center; gap: 10px; padding: 0 4px 20px; }
.an-produit .an-nom { font-size: 15px; font-weight: 600; color: var(--an-ink); line-height: 1.2; }
.an-produit .an-perimetre { font-size: 12px; color: var(--an-muted); line-height: 1.3; }
[data-testid="stSidebar"] [data-testid="stPageLink"] a {
  border-radius: var(--an-radius-control);
  padding: 6px 10px;
  min-height: 34px;
}
[data-testid="stSidebar"] [data-testid="stPageLink"] a:hover { background: var(--an-active); }
[data-testid="stSidebar"] [data-testid="stPageLink-NavLink"][aria-current="page"],
[data-testid="stSidebar"] [data-testid="stPageLink"] a[aria-current="page"] { background: var(--an-active); }
[data-testid="stSidebar"] [data-testid="stPageLink"] span { font-size: 14px; color: var(--an-ink); }
[data-testid="stSidebarUserContent"] [data-testid="stVerticalBlock"] { gap: 2px; }
.an-groupe { font-size: 12px; color: var(--an-muted); padding: 18px 10px 6px; }
.an-compte { display: flex; align-items: center; gap: 10px; padding: 24px 4px 8px; }
.an-initiales {
  flex: none; width: 30px; height: 30px; border-radius: 50%;
  background: var(--an-accent-pale); color: var(--an-accent);
  display: grid; place-items: center; font-size: 12px; font-weight: 600;
}
.an-compte .an-login { font-size: 14px; color: var(--an-ink); line-height: 1.25; }
.an-compte .an-role { font-size: 12px; color: var(--an-muted); line-height: 1.25; }

/* ---------- Ligne de titre d'une page ---------- */
.an-titre h1 { font-size: 22px; font-weight: 600; margin: 0; color: var(--an-ink); line-height: 1.3; }
.an-titre p { font-size: 14px; color: var(--an-muted); margin: 4px 0 0; max-width: 72ch; }

/* ---------- Contrôles ---------- */
.stButton button, .stDownloadButton button, [data-testid="stFormSubmitButton"] button {
  min-height: 36px; padding: 0 14px; border-radius: var(--an-radius-control); font-weight: 500;
  box-shadow: none; transition: background-color .12s ease, border-color .12s ease, transform .08s ease;
}
.stButton button:active, .stDownloadButton button:active { transform: translateY(1px); }
.stButton button[kind="secondary"], .stDownloadButton button[kind="secondary"] {
  background: var(--an-sheet); border: 1px solid var(--an-control); color: var(--an-ink);
}
.stButton button[kind="secondary"]:hover, .stDownloadButton button[kind="secondary"]:hover {
  border-color: var(--an-ink); color: var(--an-ink); background: var(--an-sheet);
}
.stButton button[kind="primary"], [data-testid="stFormSubmitButton"] button {
  background: var(--an-ink); border: 1px solid var(--an-ink); color: #ffffff;
}
.stButton button[kind="primary"]:hover, [data-testid="stFormSubmitButton"] button:hover {
  background: #2c2e31; border-color: #2c2e31; color: #ffffff;
}
.stButton button[kind="tertiary"] { color: var(--an-muted); padding: 0 8px; }
.stButton button[kind="tertiary"]:hover { color: var(--an-ink); }
[data-testid="stSidebar"] .stButton button[kind="tertiary"] { padding: 0 6px; min-height: 30px; }

.stTextArea textarea, .stTextInput input {
  background: var(--an-sheet) !important; font-size: 15px; line-height: 1.7; color: var(--an-ink);
}
.stTextArea textarea { padding: 20px 24px; }
.stTextArea [data-baseweb="textarea"], .stTextInput [data-baseweb="input"] {
  background: var(--an-sheet); border-radius: var(--an-radius-card);
}
.stTextArea [data-testid="InputInstructions"] { display: none; }

/* Import de fichier : une seule ligne au lieu d'une grande zone */
[data-testid="stFileUploaderDropzone"] {
  padding: 8px 12px; background: var(--an-raised); border: 1px dashed var(--an-control);
  border-radius: var(--an-radius-card); min-height: 0;
}
[data-testid="stFileUploaderDropzoneInstructions"] svg { display: none; }
/* Streamlit n'est pas traduit : on remplace ses deux libellés anglais */
[data-testid="stFileUploaderDropzone"] button p { display: none; }
[data-testid="stFileUploaderDropzone"] button [data-testid="stMarkdownContainer"]::after { content: "Importer un fichier"; font-size: 14px; }
[data-testid="stFileUploaderDropzoneInstructions"] span { display: none; }
[data-testid="stFileUploaderDropzoneInstructions"] > div::after { content: "Texte .txt ou .md, 1 Mo au plus"; font-size: 12px; color: var(--an-muted); }

[data-testid="stAlert"] { border-radius: var(--an-radius-card); }

/* ---------- En-tête d'un volet ---------- */
.an-volet { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; min-height: 28px; margin-bottom: 2px; }
.an-volet h2 { flex: none; white-space: nowrap; font-size: 16px; font-weight: 600; margin: 0; padding: 0; color: var(--an-ink); line-height: 1.4; }
.an-volet .an-meta { min-width: 0; overflow: hidden; text-overflow: ellipsis; font-size: 12px; color: var(--an-muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
.an-pastille {
  display: inline-block; flex: none; white-space: nowrap; font-size: 12px; font-weight: 500;
  padding: 2px 8px; border-radius: 4px; background: var(--an-warning-bg); color: var(--an-warning-ink);
}
.an-pastille.neutre { background: var(--an-active); color: #353736; }

/* ---------- Le document ---------- */
.an-page {
  height: 480px; overflow: auto; box-sizing: border-box;
  background: var(--an-sheet); border: 1px solid var(--an-border); border-radius: var(--an-radius-card);
  padding: 20px 24px; white-space: pre-wrap; overflow-wrap: anywhere;
  font-size: 15px; line-height: 1.7; color: var(--an-ink);
}
.an-page.vide {
  white-space: normal; display: flex; flex-direction: column; justify-content: center; align-items: flex-start;
  background: var(--an-raised); border-color: var(--an-raised); padding: 40px 48px;
}
.an-page.vide .an-esquisse { width: 100%; max-width: 360px; margin-bottom: 28px; }
.an-page.vide .an-esquisse i {
  display: block; height: 8px; border-radius: 2px; background: #dfe0e2; margin-bottom: 14px;
}
.an-page.vide .an-esquisse i.c { background: var(--an-ink); height: 12px; }
.an-page.vide strong { font-size: 16px; font-weight: 600; display: block; margin-bottom: 6px; }
.an-page.vide span { color: var(--an-muted); max-width: 46ch; display: block; }

/* Donnée personnelle repérée (analyse) */
.an-pii { background: var(--an-accent-pale); text-decoration: underline 1.5px var(--an-accent); text-underline-offset: 4px; border-radius: 2px; padding: 0 2px; }
.an-pii sup { white-space: nowrap; color: var(--an-accent); font-size: 11px; font-weight: 500; margin-left: 4px; vertical-align: 0.45em; }
/* Donnée masquée : le trait d'encre du caviardage, avec son marqueur */
.an-masque {
  background: var(--an-ink); color: #f4f4f1; border-radius: 2px; padding: 1px 6px;
  font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 12.5px; letter-spacing: 0;
}
/* Donnée remplacée par une valeur fictive (pseudonymisation) */
.an-pseudo { background: var(--an-accent-pale); text-decoration: underline 1.5px var(--an-accent); text-underline-offset: 4px; border-radius: 2px; padding: 0 2px; }

/* ---------- Tableau des détections ---------- */
.an-tableau { width: 100%; border-collapse: collapse; font-size: 14px; }
.an-tableau th {
  text-align: left; font-weight: 400; font-size: 12px; color: var(--an-muted);
  padding: 0 12px 8px 0; border-bottom: 1px solid var(--an-border);
}
.an-tableau td { padding: 11px 12px 11px 0; border-bottom: 1px solid var(--an-rule); vertical-align: top; color: var(--an-muted); }
.an-tableau td.id { color: var(--an-ink); }
.an-tableau .droite { text-align: right; padding-right: 0; }
.an-tableau .fleche { color: #9a9c9e; padding-right: 12px; }
.an-tableau .an-masque { font-size: 12px; }
.an-types { display: flex; flex-wrap: wrap; gap: 6px 20px; margin: 4px 0 18px; font-size: 14px; }
.an-types span { white-space: nowrap; color: var(--an-muted); }
.an-types b { font-weight: 500; color: var(--an-ink); font-variant-numeric: tabular-nums; margin-left: 4px; }
.an-defile { max-height: 420px; overflow: auto; }

@media (max-width: 1100px) {
  /* Barre d'outils : la stratégie sur sa propre ligne, les actions en dessous */
  .st-key-barre [data-testid="stHorizontalBlock"] { flex-wrap: wrap; row-gap: 8px; }
  .st-key-barre [data-testid="stColumn"] { flex: 1 1 0 !important; width: auto !important; min-width: 0 !important; }
  .st-key-barre [data-testid="stColumn"]:first-child { flex-basis: 100% !important; margin-bottom: 8px; }
  .st-key-barre [data-testid="stColumn"]:nth-child(2) { display: none; }
}

@media (max-width: 640px) {
  .st-key-barre [data-testid="stColumn"] { flex: 1 1 calc(50% - 8px) !important; }
  [data-testid="stMain"] { padding: 48px 0 0 0; }
  [data-testid="stMainBlockContainer"] { border-radius: 0; border-left: none; border-right: none; padding: 20px 16px 32px; }
  .an-page { height: 420px; padding: 16px; font-size: 15px; }
  .an-page.vide { padding: 28px 20px; }
}
</style>
"""


def appliquer() -> None:
    """Injecte la feuille de style de l'application (à appeler une fois par exécution)."""
    st.html(_CSS)


def entete(titre: str, sous_titre: str | None = None) -> None:
    """Ligne de titre d'une page : un titre de niveau 1 et une phrase d'explication."""
    phrase = f"<p>{html.escape(sous_titre)}</p>" if sous_titre else ""
    st.html(f'<div class="an-titre"><h1>{html.escape(titre)}</h1>{phrase}</div>')


def produit() -> None:
    """Nom et marque du produit, en tête de la barre latérale."""
    st.html(
        f'<div class="an-produit">{MARQUE_SVG}<div><div class="an-nom">Anonymia</div>'
        '<div class="an-perimetre">Caviardage de documents</div></div></div>'
    )


def compte(login: str, role: str) -> None:
    """Ligne de l'utilisateur connecté, en bas de la barre latérale."""
    parties = [p for p in re.split(r"[^0-9A-Za-zÀ-ÿ]+", login) if p]
    initiales = "".join(p[0] for p in parties[:2]) if len(parties) > 1 else login[:2]
    initiales = (initiales or "?").upper()
    st.html(
        f'<div class="an-compte"><span class="an-initiales">{html.escape(initiales)}</span>'
        f'<div><div class="an-login">{html.escape(login)}</div>'
        f'<div class="an-role">{html.escape(LIBELLES_ROLES.get(role, role))}</div></div></div>'
    )
