"""
Mise en forme de l'historique des traitements pour l'affichage et l'export CSV.

Ce module n'importe pas Streamlit : il se teste seul, avec de simples listes de dictionnaires.
Il reçoit les traitements tels que les renvoie l'API (GET /journaux) :
id, user_id, date_traitement, hash_document, strategie_anonymisation,
detecteurs_contributeurs, nb_pii_detectees, injection_suspectee.

injection_suspectee vaut True quand le document contenait des motifs d'injection de prompt et
que l'utilisateur a confirmé le traitement malgré l'alerte. Les traitements archivés avant
l'ajout de cette colonne n'ont pas le champ : on les considère comme non suspects.
"""
import csv
import io
from datetime import UTC, datetime, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import surlignage

FUSEAU_PAR_DEFAUT = "Europe/Paris"

COLONNES = [
    "Date",
    "Utilisateur",
    "Stratégie",
    "Détecteurs",
    "Données détectées",
    "Types de données",
    "Injection suspectée",
    "Juge LLM",
    "Empreinte du document",
]

_STRATEGIES = {"masking": "Masquage", "pseudonymization": "Pseudonymisation"}
_DETECTEURS = {"RegexDetector": "Regex", "LLMDetector": "LLM"}

# Tranches du nombre de données détectées par document (borne haute incluse), dans l'ordre d'affichage
_TRANCHES = [("0", 0), ("1 à 2", 2), ("3 à 5", 5), ("6 à 10", 10), ("Plus de 10", None)]


def fuseau(nom: str | None) -> tzinfo:
    """
    Fuseau horaire d'affichage : celui demandé, sinon Paris, sinon UTC.

    Sur certains postes (Windows sans le paquet tzdata), les fuseaux nommés sont introuvables :
    on retombe alors sur UTC plutôt que de faire planter la page.
    """
    for candidat in (nom, FUSEAU_PAR_DEFAUT):
        if candidat:
            try:
                return ZoneInfo(candidat)
            except (ZoneInfoNotFoundError, ValueError, OSError):
                continue
    return UTC


def libelle_detecteurs(contributeurs: str) -> str:
    """
    'RegexDetector,LLMDetector' -> 'Regex + LLM' ; 'RegexDetector' -> 'Regex seul'.

    Les détecteurs en panne n'apparaissent pas dans la liste : l'absence de LLM
    signale donc un traitement fait en mode dégradé (ou avec LLM_ENABLED=false).
    """
    noms = [n.strip() for n in contributeurs.split(",") if n.strip()]
    if not noms:
        return "Aucun"
    libelles = [_DETECTEURS.get(n, n) for n in noms]
    return f"{libelles[0]} seul" if len(libelles) == 1 else " + ".join(libelles)


# Types d'injection renvoyés par le juge LLM -> libellé affiché
LIBELLES_INJECTION_JUGE = {
    "ignore_instructions": "Contournement des consignes",
    "role_manipulation": "Changement de rôle",
    "prompt_extraction": "Extraction du prompt",
    "data_exfiltration": "Exfiltration de données",
    "other": "Autre tentative",
}


def libelle_juge(statut: str | None, type_injection: str | None = None) -> str:
    """
    Verdict du juge LLM en clair. « Rien repéré » ne veut pas dire « sûr » : le juge peut être trompé.

    Pas de statut (traitement sans juge) : « — ».
    """
    if statut == "detected":
        return "Injection : " + LIBELLES_INJECTION_JUGE.get(type_injection or "", type_injection or "type inconnu")
    if statut == "not_detected":
        return "Rien repéré"
    if statut == "unavailable":
        return "Indisponible"
    return "—"


def injection_suspectee(traitement: dict) -> bool:
    """Vrai si le traitement a été fait malgré des motifs d'injection de prompt (absent = faux)."""
    return bool(traitement.get("injection_suspectee", False))


def regrouper_types(types_pii: dict[str, int] | None) -> dict[str, int]:
    """
    Nombre de PII par libellé lisible, du plus fréquent au plus rare.

    Les trois types de plaques d'immatriculation partagent le libellé « Plaque » : leurs nombres
    s'additionnent.
    """
    regroupe: dict[str, int] = {}
    for type_pii, nombre in (types_pii or {}).items():
        nom = surlignage.libelle(type_pii)
        regroupe[nom] = regroupe.get(nom, 0) + nombre
    return dict(sorted(regroupe.items(), key=lambda element: (-element[1], element[0])))


def libelle_types(types_pii: dict[str, int] | None) -> str:
    """{'EMAIL': 2, 'NOM': 1} -> '2 E-mail · 1 Nom' ; '—' pour un traitement sans types (ancien)."""
    regroupe = regrouper_types(types_pii)
    return " · ".join(f"{nombre} {nom}" for nom, nombre in regroupe.items()) if regroupe else "—"


def _date_locale(texte: str, tz: tzinfo) -> datetime:
    """Date ISO renvoyée par l'API (en UTC) convertie dans le fuseau d'affichage, sans fuseau attaché."""
    date = datetime.fromisoformat(texte)
    if date.tzinfo is None:
        date = date.replace(tzinfo=UTC)
    return date.astimezone(tz).replace(tzinfo=None)


def formater_date(texte: str | None, tz: tzinfo, defaut: str = "—") -> str:
    """Date ISO renvoyée par l'API affichée en JJ/MM/AAAA HH:MM dans le fuseau d'affichage (defaut si absente)."""
    if not texte:
        return defaut
    try:
        return _date_locale(texte, tz).strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return defaut


def lignes_tableau(
    traitements: list[dict], logins: dict[int, str], tz: tzinfo, hash_complet: bool = False
) -> list[dict]:
    """
    Une ligne par traitement, avec les colonnes de COLONNES.

    logins : correspondance id -> login (vide si inconnue : seul un administrateur peut la lire).
    L'utilisateur est alors affiché par son numéro.
    """
    lignes = []
    for t in traitements:
        empreinte = t["hash_document"]
        lignes.append(
            {
                "Date": _date_locale(t["date_traitement"], tz),
                "Utilisateur": logins.get(t["user_id"]) or f"n°{t['user_id']}",
                "Stratégie": _STRATEGIES.get(t["strategie_anonymisation"], t["strategie_anonymisation"]),
                "Détecteurs": libelle_detecteurs(t["detecteurs_contributeurs"]),
                "Données détectées": t["nb_pii_detectees"],
                "Types de données": libelle_types(t.get("types_pii")),
                "Injection suspectée": injection_suspectee(t),
                "Juge LLM": libelle_juge(t.get("juge_statut"), t.get("juge_type")),
                "Empreinte du document": empreinte if hash_complet else empreinte[:12] + "…",
            }
        )
    return lignes


def statistiques(traitements: list[dict], tz: tzinfo) -> dict:
    """Totaux affichés en haut de page et nombre de traitements par jour (jours dans le fuseau d'affichage)."""
    par_jour: dict[str, int] = {}
    for t in traitements:
        jour = _date_locale(t["date_traitement"], tz).date().isoformat()
        par_jour[jour] = par_jour.get(jour, 0) + 1
    return {
        "traitements": len(traitements),
        "pii": sum(t["nb_pii_detectees"] for t in traitements),
        "utilisateurs": len({t["user_id"] for t in traitements}),
        "injections": sum(injection_suspectee(t) for t in traitements),
        "par_jour": dict(sorted(par_jour.items())),
    }


def _tranche(nb_pii: int) -> str:
    """Nom de la tranche (« 0 », « 1 à 2 »...) dans laquelle tombe un nombre de données détectées."""
    for nom, borne in _TRANCHES:
        if borne is None or nb_pii <= borne:
            return nom
    return _TRANCHES[-1][0]


def tableau_de_bord(traitements: list[dict], logins: dict[int, str], tz: tzinfo) -> dict:
    """
    Agrégats de la page Tableau de bord, calculés sur les traitements renvoyés par l'API.

    Les répartitions (par utilisateur, stratégie, détecteurs) sont triées de la plus grande à la plus
    petite. « sans_llm » compte les traitements où le LLM n'a pas contribué : mode dégradé (LLM en
    panne) ou application lancée avec LLM_ENABLED=false.
    """
    base = statistiques(traitements, tz)
    total = base["traitements"]

    par_utilisateur: dict[str, int] = {}
    detail_utilisateur: dict[str, dict] = {}
    par_strategie: dict[str, int] = {}
    par_detecteurs: dict[str, int] = {}
    par_tranche = {nom: 0 for nom, _ in _TRANCHES}
    juge = {"detected": 0, "not_detected": 0, "unavailable": 0, "sans_juge": 0}
    par_type: dict[str, int] = {}
    sans_types = 0
    sans_llm = 0
    pii_max = 0
    for t in traitements:
        nom = logins.get(t["user_id"]) or f"n°{t['user_id']}"
        par_utilisateur[nom] = par_utilisateur.get(nom, 0) + 1

        juge[t.get("juge_statut") if t.get("juge_statut") in juge else "sans_juge"] += 1

        types = regrouper_types(t.get("types_pii"))
        if types or t["nb_pii_detectees"] == 0:
            for nom_type, nombre in types.items():
                par_type[nom_type] = par_type.get(nom_type, 0) + nombre
        else:
            sans_types += 1  # traitement enregistré avant l'ajout des types

        nb_pii = t["nb_pii_detectees"]
        pii_max = max(pii_max, nb_pii)
        par_tranche[_tranche(nb_pii)] += 1
        ligne = detail_utilisateur.setdefault(nom, {"traitements": 0, "pii": 0, "dernier": None})
        ligne["traitements"] += 1
        ligne["pii"] += nb_pii
        date = _date_locale(t["date_traitement"], tz)
        if ligne["dernier"] is None or date > ligne["dernier"]:
            ligne["dernier"] = date

        strategie = _STRATEGIES.get(t["strategie_anonymisation"], t["strategie_anonymisation"])
        par_strategie[strategie] = par_strategie.get(strategie, 0) + 1

        libelle = libelle_detecteurs(t["detecteurs_contributeurs"])
        par_detecteurs[libelle] = par_detecteurs.get(libelle, 0) + 1

        if "LLMDetector" not in t["detecteurs_contributeurs"].split(","):
            sans_llm += 1

    def trier(repartition: dict[str, int]) -> dict[str, int]:
        return dict(sorted(repartition.items(), key=lambda element: (-element[1], element[0])))

    detail = [
        {
            "Utilisateur": nom,
            "Traitements": d["traitements"],
            "Données détectées": d["pii"],
            "Moyenne par document": round(d["pii"] / d["traitements"], 1),
            "Dernier traitement": d["dernier"],
        }
        for nom, d in detail_utilisateur.items()
    ]
    detail.sort(key=lambda ligne: (-ligne["Traitements"], ligne["Utilisateur"]))

    return {
        "traitements": total,
        "pii": base["pii"],
        "utilisateurs": base["utilisateurs"],
        "pii_moyenne": round(base["pii"] / total, 1) if total else 0.0,
        "pii_max": pii_max,
        "par_tranche": par_tranche,
        "juge": juge,
        "par_type": trier(par_type),
        "traitements_sans_types": sans_types,
        "detail_utilisateurs": detail,
        "sans_llm": sans_llm,
        "part_sans_llm": round(100 * sans_llm / total) if total else 0,
        "par_jour": base["par_jour"],
        "par_utilisateur": trier(par_utilisateur),
        "par_strategie": trier(par_strategie),
        "par_detecteurs": trier(par_detecteurs),
    }


def _proteger(valeur):
    """
    Neutralise l'injection de formules : Excel exécute une cellule texte qui commence par = + - @.

    On préfixe alors d'une apostrophe. Les nombres et les dates ne sont pas concernés.
    """
    if isinstance(valeur, bool):
        return "Oui" if valeur else "Non"
    if isinstance(valeur, str) and valeur[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + valeur
    return valeur


def vers_csv(lignes: list[dict]) -> bytes:
    """
    CSV prêt à ouvrir dans Excel en français : séparateur « ; » et UTF-8 avec BOM (accents lisibles).

    Les empreintes doivent être complètes : passer des lignes créées avec hash_complet=True.
    """
    sortie = io.StringIO()
    ecrivain = csv.writer(sortie, delimiter=";", lineterminator="\r\n")
    ecrivain.writerow(COLONNES)
    for ligne in lignes:
        ecrivain.writerow(
            [
                ligne[c].strftime("%Y-%m-%d %H:%M:%S") if isinstance(ligne[c], datetime) else _proteger(ligne[c])
                for c in COLONNES
            ]
        )
    return sortie.getvalue().encode("utf-8-sig")
