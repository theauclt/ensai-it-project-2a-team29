"""
Graphiques du tableau de bord (Altair, déjà installé avec Streamlit).

Ce module n'importe pas Streamlit : chaque fonction renvoie un graphique que la page affiche avec
st.altair_chart. Les couleurs viennent d'une seule palette, pour que la page reste cohérente.
"""
import altair as alt

COULEUR = "#4C78A8"  # bleu des barres
COULEUR_ALERTE = "#E45756"  # rouge, pour ce qui demande de l'attention
PALETTE = ["#4C78A8", "#F58518", "#54A24B", "#B279A2", "#9D755D"]


def _infobulle(colonne: str, mesure: str = "Traitements") -> list[alt.Tooltip]:
    """Texte affiché au survol : catégorie, nombre et part du total."""
    return [alt.Tooltip(f"{colonne}:N"), alt.Tooltip(f"{mesure}:Q"), alt.Tooltip("Part:N")]


def _donnees(repartition: dict[str, int], colonne: str, mesure: str = "Traitements") -> list[dict]:
    total = sum(repartition.values()) or 1
    return [
        {colonne: nom, mesure: n, "Part": f"{round(100 * n / total)} %"}
        for nom, n in repartition.items()
    ]


def barres_horizontales(repartition: dict[str, int], colonne: str, mesure: str = "Traitements") -> alt.Chart:
    """
    Barres horizontales triées de la plus grande à la plus petite, avec la valeur au bout.

    mesure : ce que comptent les barres (« Traitements » par défaut, « Données » pour les types).
    """
    donnees = _donnees(repartition, colonne, mesure)
    base = alt.Chart(alt.Data(values=donnees)).encode(
        y=alt.Y(f"{colonne}:N", sort=list(repartition), title=None, axis=alt.Axis(labelLimit=200)),
        x=alt.X(f"{mesure}:Q", title=None, axis=alt.Axis(tickMinStep=1, grid=True)),
        tooltip=_infobulle(colonne, mesure),
    )
    barres = base.mark_bar(color=COULEUR, cornerRadiusEnd=4, size=22)
    valeurs = base.mark_text(align="left", dx=5, color="gray").encode(text=f"{mesure}:Q")
    return (barres + valeurs).properties(height=max(110, 42 * len(donnees)))


def barres_verticales(repartition: dict[str, int], colonne: str, couleur: str = COULEUR) -> alt.Chart:
    """Barres verticales dans l'ordre du dictionnaire (jours, tranches...), avec la valeur au-dessus."""
    donnees = _donnees(repartition, colonne)
    base = alt.Chart(alt.Data(values=donnees)).encode(
        x=alt.X(f"{colonne}:N", sort=list(repartition), title=None, axis=alt.Axis(labelAngle=0)),
        y=alt.Y("Traitements:Q", title=None, axis=alt.Axis(tickMinStep=1, grid=True)),
        tooltip=_infobulle(colonne),
    )
    barres = base.mark_bar(color=couleur, cornerRadiusEnd=4)
    valeurs = base.mark_text(dy=-8, color="gray").encode(text="Traitements:Q")
    return (barres + valeurs).properties(height=260)


def anneau(repartition: dict[str, int], colonne: str) -> alt.Chart:
    """Diagramme en anneau : la part de chaque catégorie dans le total."""
    donnees = _donnees(repartition, colonne)
    return (
        alt.Chart(alt.Data(values=donnees))
        .mark_arc(innerRadius=55, stroke="white", strokeWidth=2)
        .encode(
            theta=alt.Theta("Traitements:Q"),
            color=alt.Color(
                f"{colonne}:N",
                scale=alt.Scale(domain=list(repartition), range=PALETTE),
                legend=alt.Legend(title=None, orient="bottom"),
            ),
            tooltip=_infobulle(colonne),
        )
        .properties(height=260)
    )
