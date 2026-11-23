"""Graphiques PNG pour le rapport, à partir des résultats de scripts.evaluer_corpus.

Appelé par evaluer_corpus (dossier de sortie / graphiques/). Nécessite matplotlib.
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

SURFACE = "#fcfcfb"
ENCRE = "#0b0b0b"
ENCRE_2 = "#52514e"
GRILLE = "#e1e0d9"
BLEU, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"  # ordre fixe : précision, rappel, F1
RAMPE = LinearSegmentedColormap.from_list("bleu", ["#fcfcfb", "#cde2fb", "#6da7ec", "#256abf", "#0d366b"])

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "text.color": ENCRE, "axes.labelcolor": ENCRE_2, "xtick.color": ENCRE_2, "ytick.color": ENCRE_2,
    "axes.edgecolor": GRILLE, "font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
})


def _sauver(fig, chemin: Path) -> None:
    fig.savefig(chemin, dpi=200, bbox_inches="tight")
    plt.close(fig)


def _grille(ax, axe="x") -> None:
    ax.grid(axis=axe, color=GRILLE, linewidth=0.8)
    ax.set_axisbelow(True)


def matrice_confusion(confusion: dict, types: list[str], chemin: Path, titre: str) -> None:
    """Lignes : type attendu (+ faux positifs). Colonnes : type prédit (+ non détecté)."""
    lignes = [*types, "FAUX POSITIF"]
    colonnes = [*types, "NON DÉTECTÉ"]
    n, m = len(lignes), len(colonnes)
    vals = [[confusion.get((lg, co), 0) for co in colonnes] for lg in lignes]
    # couleur = part de la ligne ; la ligne des faux positifs est normalisée sur son total
    parts = []
    for ligne in vals:
        tot = sum(ligne)
        parts.append([v / tot if tot else 0 for v in ligne])
    fig, ax = plt.subplots(figsize=(1 + 0.85 * m, 1 + 0.7 * n))
    ax.imshow(parts, cmap=RAMPE, vmin=0, vmax=1, aspect="auto")
    for i in range(n):
        for j in range(m):
            v = vals[i][j]
            if v:
                ax.text(j, i, str(v), ha="center", va="center", fontsize=10,
                        color="#ffffff" if parts[i][j] > 0.5 else ENCRE)
    ax.set_xticks(range(m), colonnes, rotation=40, ha="right")
    ax.set_yticks(range(n), lignes)
    ax.set_xlabel("Type prédit par Anonymia")
    ax.set_ylabel("Type attendu (grille de vérité)")
    ax.set_xticks([x - 0.5 for x in range(m + 1)], minor=True)
    ax.set_yticks([y - 0.5 for y in range(n + 1)], minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2)
    ax.tick_params(which="both", length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title(titre, loc="left", color=ENCRE, fontsize=11)
    _sauver(fig, chemin)


def _barres_groupees(ax, noms, series, couleurs, etiquettes, valeurs_max=1.0) -> None:
    """Barres horizontales groupées (une série par couleur), valeurs écrites au bout."""
    k = len(series)
    h = 0.8 / k
    for i, (nom, vals) in enumerate(series.items()):
        ys = [y + (i - (k - 1) / 2) * h for y in range(len(noms))]
        ax.barh(ys, [v or 0 for v in vals], height=h * 0.85, color=couleurs[i], label=nom)
        for y, v in zip(ys, vals):
            ax.text((v or 0) + 0.01, y, "n/a" if v is None else f"{100 * v:.0f}", va="center",
                    fontsize=8, color=ENCRE_2)
    ax.set_yticks(range(len(noms)), etiquettes)
    ax.invert_yaxis()
    ax.set_xlim(0, valeurs_max * 1.08)
    ax.set_xticks([0, .25, .5, .75, 1], ["0", "25", "50", "75", "100"])
    ax.set_xlabel("%")
    _grille(ax, "x")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=k, frameon=False)


def prf_par_type(par_type: dict, chemin: Path, titre: str) -> None:
    types = list(par_type)
    series = {"Précision": [par_type[t]["precision"] for t in types],
              "Rappel": [par_type[t]["rappel"] for t in types],
              "F1": [par_type[t]["f1"] for t in types]}
    fig, ax = plt.subplots(figsize=(7, 0.55 * len(types) + 1.4))
    _barres_groupees(ax, types, series, [BLEU, ORANGE, AQUA], types)
    ax.set_title(titre, loc="left", color=ENCRE, fontsize=11, pad=28)
    _sauver(fig, chemin)


def prf_par_longueur(par_longueur: dict, chemin: Path, titre: str) -> None:
    noms = list(par_longueur)
    series = {"Précision": [par_longueur[k]["precision"] for k in noms],
              "Rappel": [par_longueur[k]["rappel"] for k in noms]}
    fig, ax = plt.subplots(figsize=(7, 0.7 * len(noms) + 1.4))
    _barres_groupees(ax, noms, series, [BLEU, ORANGE], noms)
    ax.set_title(titre, loc="left", color=ENCRE, fontsize=11, pad=28)
    _sauver(fig, chemin)


def _barres_simples(noms, valeurs, etiquettes_fin, chemin, titre, xlabel) -> None:
    fig, ax = plt.subplots(figsize=(7, 0.55 * len(noms) + 1.1))
    ax.barh(range(len(noms)), [v or 0 for v in valeurs], height=0.55, color=BLEU)
    for y, v, e in zip(range(len(noms)), valeurs, etiquettes_fin):
        ax.text((v or 0) + 0.01, y, e, va="center", fontsize=9, color=ENCRE_2)
    ax.set_yticks(range(len(noms)), noms)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.18)
    ax.set_xticks([0, .25, .5, .75, 1], ["0", "25", "50", "75", "100"])
    ax.set_xlabel(xlabel)
    _grille(ax, "x")
    ax.set_title(titre, loc="left", color=ENCRE, fontsize=11)
    _sauver(fig, chemin)


def rappel_par_cercle(par_cercle: dict, chemin: Path, titre: str) -> None:
    noms = [f"Cercle {k}" for k in par_cercle]
    vals = [v["rappel"] for v in par_cercle.values()]
    fins = [f"{100 * (v['rappel'] or 0):.0f} %  ({v['trouves']}/{v['total']})" for v in par_cercle.values()]
    _barres_simples(noms, vals, fins, chemin, titre, "Rappel (%)")


def filtre_injection(fi: dict, chemin: Path, titre: str) -> None:
    fam = fi["par_type_attaque"]
    if not fam:
        return
    noms = list(fam)
    vals = [v["detectes"] / v["total"] if v["total"] else None for v in fam.values()]
    fins = [f"{v['detectes']}/{v['total']}" for v in fam.values()]
    _barres_simples(noms, vals, fins, chemin, titre, "Documents d'attaque détectés (%)")


def tout_tracer(resultats: dict, confusion: dict, types: list[str], dossier: Path) -> list[Path]:
    dossier.mkdir(parents=True, exist_ok=True)
    p = resultats["pipeline"]
    fichiers = [
        (dossier / "matrice_confusion.png", lambda c: matrice_confusion(confusion, types, c, f"Matrice de confusion ({p})")),
        (dossier / "precision_rappel_par_type.png", lambda c: prf_par_type(resultats["par_type"], c, f"Précision, rappel et F1 par type ({p})")),
        (dossier / "rappel_par_cercle.png", lambda c: rappel_par_cercle(resultats["par_cercle"], c, f"Rappel par cercle ({p})")),
        (dossier / "par_longueur.png", lambda c: prf_par_longueur(resultats["par_longueur"], c, f"Précision et rappel par longueur de document ({p})")),
        (dossier / "filtre_injection.png", lambda c: filtre_injection(resultats["filtre_injection"], c, "Filtre d'injection : détection par famille d'attaque")),
    ]
    for chemin, f in fichiers:
        f(chemin)
    return [c for c, _ in fichiers if c.exists()]