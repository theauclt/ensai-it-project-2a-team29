"""
Évalue le pipeline Anonymia sur le corpus de test (grille de vérité).

Usage (depuis la racine du dépôt) :
    python -m scripts.evaluer_corpus corpus-test                 # regex seul
    python -m scripts.evaluer_corpus corpus-test --llm           # regex + LLM (Datalab)
    python -m scripts.evaluer_corpus corpus-test --sortie resultats

Écrit dans le dossier de sortie : metriques.md (tableaux pour le rapport),
metriques.json, details_par_document.csv et erreurs.csv (faux positifs/négatifs).
Aucune base de données n'est utilisée : seul le pipeline de détection est évalué.
"""
import argparse
import asyncio
import csv
import json
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv

from anonymia.infrastructure.anonymization_strategy_factory import (
    AnonymizationStrategyFactory,
)
from anonymia.infrastructure.regex_detector import RegexDetector
from anonymia.service.detection_service import DetectionService
from anonymia.service.prompt_injector_detector import PromptInjectionDetector

# Types d'Anonymia -> types de la grille
MAPPING = {
    "EMAIL": "EMAIL",
    "TELEPHONE": "PHONE",
    "NIR": "NIR",
    "IBAN": "IBAN",
    "PLAQUE_ACTUELLE": "LICENSE_PLATE",
    "PLAQUE_ANCIENNE": "LICENSE_PLATE",
    "PLAQUE_DIPLOMATIQUE": "LICENSE_PLATE",
    "NOM": "PERSON",
    "PRENOM": "PERSON",
    "LIEU": "LOCATION",
    "ORGANISATION": "ORG",
    "ADRESSE": "ADDRESS_FULL",
    "DATE_NAISSANCE": "DATE_OF_BIRTH",
    "POSTE": "JOB_TITLE",
}
TYPES_REGEX = {"EMAIL", "PHONE", "NIR", "IBAN", "LICENSE_PLATE"}
TYPES_LLM = {"PERSON", "LOCATION", "ORG", "ADDRESS_FULL", "DATE_OF_BIRTH", "JOB_TITLE"}
# Types que le projet ne traite pas par choix (cercle 3 + passeport)
HORS_PERIMETRE = {"PASSPORT", "INTERNAL_ID", "RELATIVE", "PUBLIC_FIGURE"}
# Convention de la grille : seul le span le plus englobant est enregistré
ENGLOBANTS = {"ADDRESS_FULL", "ORG"}


def chevauche(a, b) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def contenu_dans(petit, grand) -> bool:
    return grand[0] <= petit[0] and petit[1] <= grand[1]


def fusionner_personnes(spans: list[dict], texte: str) -> list[dict]:
    """NOM et PRENOM séparés par des espaces seulement forment une PERSON."""
    spans = sorted(spans, key=lambda s: s["start"])
    resultat: list[dict] = []
    for s in spans:
        precedent = resultat[-1] if resultat else None
        if (
            precedent
            and s["type"] == "PERSON" == precedent["type"]
            and texte[precedent["end"]: s["start"]].strip(" \t-'") == ""
            and s["start"] - precedent["end"] <= 2
        ):
            precedent["end"] = max(precedent["end"], s["end"])
        else:
            resultat.append(dict(s))
    return resultat


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "rappel": r, "f1": f}


def pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.1f} %"


def construire_service(avec_llm: bool) -> DetectionService:
    detecteurs = [RegexDetector()]
    if avec_llm:
        from anonymia.dependencies import build_llm_detector

        detecteurs.append(build_llm_detector())
    return DetectionService(
        detectors=detecteurs,
        strategy_factory=AnonymizationStrategyFactory(),
        archive_repo=None,  # aucune base : on n'utilise que analyze()
        injection_detector=PromptInjectionDetector(),
    )


async def evaluer(corpus: Path, avec_llm: bool, sortie: Path) -> None:
    docs_dir = corpus / "documents"
    manifest = {
        r["doc_id"]: r
        for r in csv.DictReader(open(corpus / "grille_verite/manifest_documents.csv", encoding="utf-8"))
    }
    verite: dict[str, list[dict]] = defaultdict(list)
    for r in csv.DictReader(open(corpus / "grille_verite/ground_truth_spans.csv", encoding="utf-8")):
        verite[r["doc_id"]].append(
            {**r, "start": int(r["start"]), "end": int(r["end"]), "cercle": int(r["cercle"])}
        )

    perimetre = TYPES_REGEX | (TYPES_LLM if avec_llm else set())
    service = construire_service(avec_llm)
    injection = PromptInjectionDetector()

    par_type = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tp_strict": 0})
    par_cercle = defaultdict(lambda: [0, 0])  # [trouvés, total]
    par_longueur = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    par_doc_type = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    details, erreurs, ignores = [], [], 0
    sans_pii = {"docs": 0, "docs_avec_fp": 0, "fp": 0}
    securite_lignes = []
    pannes = 0

    for doc_id in sorted(manifest):
        meta = manifest[doc_id]
        with open(docs_dir / doc_id, encoding="utf-8", newline="") as f:
            texte = f.read()
        gold = verite.get(doc_id, [])
        for g in gold:
            assert texte[g["start"]: g["end"]] == g["text"], f"grille incohérente : {doc_id}"

        # --- détection de PII (le pipeline réel : détecteurs en parallèle + fusion)
        try:
            spans = await service.analyze(texte)
        except Exception as exc:  # noqa: BLE001
            pannes += 1
            spans = []
            print(f"! {doc_id} : {type(exc).__name__}")
        preds = [
            {"type": MAPPING.get(s.type, s.type), "start": s.start, "end": s.end,
             "texte": s.text, "detecteur": s.source_detector}
            for s in spans
        ]
        preds = fusionner_personnes(preds, texte)
        preds = [p for p in preds if p["type"] in perimetre]

        gold_perimetre = [g for g in gold if g["pii_type"] in perimetre]
        tp = fp = fn = 0
        for g in gold:
            rang = (g["start"], g["end"])
            trouve = any(
                p["type"] == g["pii_type"] and chevauche((p["start"], p["end"]), rang) for p in preds
            )
            exact = any(
                p["type"] == g["pii_type"] and (p["start"], p["end"]) == rang for p in preds
            )
            if g["pii_type"] in perimetre:
                par_cercle[g["cercle"]][1] += 1
                if trouve:
                    par_cercle[g["cercle"]][0] += 1
                    par_type[g["pii_type"]]["tp"] += 1
                    par_type[g["pii_type"]]["tp_strict"] += exact
                    tp += 1
                else:
                    par_type[g["pii_type"]]["fn"] += 1
                    fn += 1
                    erreurs.append([doc_id, "faux_negatif", g["pii_type"], g["text"], "", meta["type_document"]])
        for p in preds:
            rang = (p["start"], p["end"])
            if any(g["pii_type"] == p["type"] and chevauche(rang, (g["start"], g["end"])) for g in gold):
                continue
            # imbriqué dans un span englobant de la grille : pas un faux positif (convention)
            if any(
                g["pii_type"] in ENGLOBANTS and g["pii_type"] != p["type"]
                and contenu_dans(rang, (g["start"], g["end"]))
                for g in gold
            ):
                ignores += 1
                continue
            par_type[p["type"]]["fp"] += 1
            fp += 1
            erreurs.append([doc_id, "faux_positif", p["type"], p["texte"], p["detecteur"], meta["type_document"]])

        for table, cle in ((par_longueur, meta["categorie_longueur"]), (par_doc_type, meta["type_document"])):
            table[cle]["tp"] += tp
            table[cle]["fp"] += fp
            table[cle]["fn"] += fn
        if meta["contient_pii"] == "non":
            sans_pii["docs"] += 1
            sans_pii["fp"] += fp
            sans_pii["docs_avec_fp"] += fp > 0
        details.append([doc_id, meta["type_document"], meta["categorie_longueur"],
                        len(gold_perimetre), tp, fp, fn])

        # --- filtre d'injection (indépendant du LLM)
        categories = injection.detect(texte)
        securite_lignes.append((doc_id, meta["test_adversarial"] == "oui", meta["type_attaque"], categories))

    # ------------------------------------------------------------------ sortie
    sortie.mkdir(parents=True, exist_ok=True)
    total = {"tp": 0, "fp": 0, "fn": 0, "tp_strict": 0}
    for t in par_type.values():
        for k in total:
            total[k] += t[k]
    resultats = {
        "pipeline": "regex + LLM" if avec_llm else "regex seul",
        "documents": len(manifest),
        "global": prf(total["tp"], total["fp"], total["fn"]),
        "global_strict": prf(total["tp_strict"], total["fp"], total["fn"] + total["tp"] - total["tp_strict"]),
        "par_type": {k: prf(v["tp"], v["fp"], v["fn"]) | {"tp_strict": v["tp_strict"]} for k, v in sorted(par_type.items())},
        "par_cercle": {str(k): {"trouves": v[0], "total": v[1], "rappel": v[0] / v[1] if v[1] else None}
                       for k, v in sorted(par_cercle.items())},
        "par_longueur": {k: prf(**v) for k, v in sorted(par_longueur.items())},
        "par_type_document": {k: prf(**v) for k, v in sorted(par_doc_type.items())},
        "documents_sans_pii": sans_pii,
        "faux_positifs_imbriques_ignores": ignores,
        "documents_en_panne": pannes,
    }

    attaque = [x for x in securite_lignes if x[1]]
    normaux = [x for x in securite_lignes if not x[1]]
    detectees = [x for x in attaque if x[3]]
    fp_filtre = [x for x in normaux if x[3]]
    par_attaque = defaultdict(lambda: [0, 0])
    for _, _, type_attaque, cats in attaque:
        par_attaque[type_attaque][1] += 1
        par_attaque[type_attaque][0] += bool(cats)
    resultats["filtre_injection"] = {
        "documents_attaque": len(attaque),
        "detectes": len(detectees),
        "taux_detection": len(detectees) / len(attaque) if attaque else None,
        "documents_normaux": len(normaux),
        "faux_positifs": len(fp_filtre),
        "taux_faux_positifs": len(fp_filtre) / len(normaux) if normaux else None,
        "par_type_attaque": {k: {"detectes": v[0], "total": v[1]} for k, v in sorted(par_attaque.items())},
        "non_detectes": [(d, t) for d, _, t, c in attaque if not c],
        "faux_positifs_docs": [d for d, _, _, c in normaux if c],
    }
    (sortie / "metriques.json").write_text(json.dumps(resultats, ensure_ascii=False, indent=2), encoding="utf-8")
    with open(sortie / "details_par_document.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["doc_id", "type_document", "longueur", "nb_pii_attendues", "tp", "fp", "fn"])
        w.writerows(details)
    with open(sortie / "erreurs.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["doc_id", "erreur", "type", "texte", "detecteur", "type_document"])
        w.writerows(erreurs)

    md = [f"# Évaluation sur le corpus de test ({resultats['pipeline']})", ""]
    g, gs = resultats["global"], resultats["global_strict"]
    md += ["## Détection des PII", "",
           f"Périmètre évalué : {', '.join(sorted(perimetre))}. Correspondance : même type et recouvrement.", "",
           "| | Précision | Rappel | F1 | TP | FP | FN |", "|---|---|---|---|---|---|---|",
           f"| Global (recouvrement) | {pct(g['precision'])} | {pct(g['rappel'])} | {pct(g['f1'])} | {g['tp']} | {g['fp']} | {g['fn']} |",
           f"| Global (positions exactes) | {pct(gs['precision'])} | {pct(gs['rappel'])} | {pct(gs['f1'])} | {gs['tp']} | {gs['fp']} | {gs['fn']} |",
           "", "### Par type", "", "| Type | Précision | Rappel | F1 | TP | FP | FN |", "|---|---|---|---|---|---|---|"]
    for k, v in resultats["par_type"].items():
        md.append(f"| {k} | {pct(v['precision'])} | {pct(v['rappel'])} | {pct(v['f1'])} | {v['tp']} | {v['fp']} | {v['fn']} |")
    md += ["", "### Rappel par cercle (types du périmètre)", "", "| Cercle | Trouvées | Total | Rappel |", "|---|---|---|---|"]
    for k, v in resultats["par_cercle"].items():
        md.append(f"| {k} | {v['trouves']} | {v['total']} | {pct(v['rappel'])} |")
    md += ["", "### Par longueur de document", "", "| Longueur | Précision | Rappel | TP | FP | FN |", "|---|---|---|---|---|---|"]
    for k, v in resultats["par_longueur"].items():
        md.append(f"| {k} | {pct(v['precision'])} | {pct(v['rappel'])} | {v['tp']} | {v['fp']} | {v['fn']} |")
    s = resultats["documents_sans_pii"]
    md += ["", "### Documents sans PII (faux positifs)", "",
           f"{s['docs_avec_fp']} document(s) sur {s['docs']} contiennent au moins un faux positif ({s['fp']} au total).",
           f"Faux positifs imbriqués ignorés (convention de la grille) : {ignores}.", ""]
    fi = resultats["filtre_injection"]
    md += ["## Filtre d'injection de prompt", "",
           f"- Documents d'attaque détectés : {fi['detectes']} / {fi['documents_attaque']} ({pct(fi['taux_detection'])})",
           f"- Faux positifs sur documents normaux : {fi['faux_positifs']} / {fi['documents_normaux']} ({pct(fi['taux_faux_positifs'])})",
           "", "| Famille d'attaque | Détectés | Total |", "|---|---|---|"]
    for k, v in fi["par_type_attaque"].items():
        md.append(f"| {k} | {v['detectes']} | {v['total']} |")
    md += ["", "Non détectés : " + (", ".join(f"{d} ({t})" for d, t in fi["non_detectes"]) or "aucun"),
           "Faux positifs : " + (", ".join(fi["faux_positifs_docs"]) or "aucun")]
    (sortie / "metriques.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    await service.aclose()


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus", type=Path, help="dossier corpus-test")
    parser.add_argument("--llm", action="store_true", help="ajoute le détecteur LLM (variables LLM_* du .env)")
    parser.add_argument("--sortie", type=Path, default=Path("resultats_evaluation"))
    args = parser.parse_args()
    asyncio.run(evaluer(args.corpus, args.llm, args.sortie))


if __name__ == "__main__":
    main()