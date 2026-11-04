"""
Évalue le juge d'injection LLM (FO3) sur le corpus de test.

Usage (depuis la racine du dépôt, avec les variables LLM_* du .env) :
    python -m scripts.evaluer_juge corpus-test
    python -m scripts.evaluer_juge corpus-test --sortie resultats_juge --concurrence 2

Le juge est appelé directement, une fois par document (68 appels au LLM), sans base de données.
Les documents marqués test_adversarial = oui dans le manifeste doivent être « detected » ; les autres
doivent être « not_detected » (sinon : faux positif). Un verdict « unavailable » n'est ni l'un ni l'autre :
il est compté à part. Le filtre à motifs de F5 est évalué sur les mêmes documents, pour voir ce que le
juge apporte en plus.

Écrit dans le dossier de sortie : metriques_juge.md (tableaux pour le rapport), metriques_juge.json
et erreurs_juge.csv.
"""
import argparse
import asyncio
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from dotenv import load_dotenv

from anonymia.service.business_objects.injection_verdict import metadonnees_juge
from anonymia.service.interfaces.injection_judge import InjectionJudge
from anonymia.service.prompt_injector_detector import PromptInjectionDetector


def pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.1f} %"


def taux(partie: int, total: int) -> float | None:
    return partie / total if total else None


async def _verdict(juge: InjectionJudge, texte: str, limite: asyncio.Semaphore) -> tuple[str, str | None]:
    """(statut, type) du juge ; toute erreur du juge compte comme « unavailable »."""
    async with limite:
        try:
            verdict = await juge.analyze(texte)
        except Exception:  # noqa: BLE001 - le juge ne doit pas faire échouer l'évaluation
            return "unavailable", None
    statut, type_injection = metadonnees_juge(verdict)
    return statut or "unavailable", type_injection


async def evaluer(corpus: Path, juge: InjectionJudge, concurrence: int = 4) -> dict:
    """Fait juger tous les documents du corpus et calcule les indicateurs."""
    with open(corpus / "grille_verite/manifest_documents.csv", encoding="utf-8") as f:
        manifeste = {r["doc_id"]: r for r in csv.DictReader(f)}
    textes = {}
    for doc_id in manifeste:
        with open(corpus / "documents" / doc_id, encoding="utf-8", newline="") as f:
            textes[doc_id] = f.read()

    limite = asyncio.Semaphore(concurrence)
    ordre = sorted(manifeste)
    verdicts = dict(zip(
        ordre, await asyncio.gather(*(_verdict(juge, textes[d], limite) for d in ordre)), strict=True
    ))
    filtre = PromptInjectionDetector()

    attaques = [d for d in ordre if manifeste[d]["test_adversarial"] == "oui"]
    normaux = [d for d in ordre if manifeste[d]["test_adversarial"] != "oui"]

    def statut(doc_id: str) -> str:
        return verdicts[doc_id][0]

    par_attaque = defaultdict(lambda: {"detectes": 0, "total": 0, "indisponibles": 0})
    for d in attaques:
        ligne = par_attaque[manifeste[d]["type_attaque"]]
        ligne["total"] += 1
        ligne["detectes"] += statut(d) == "detected"
        ligne["indisponibles"] += statut(d) == "unavailable"

    # Ce que le juge apporte par rapport au filtre à motifs de F5, sur les documents d'attaque
    par_filtre = {d: bool(filtre.detect(textes[d])) for d in attaques}
    complementarite = {
        "les_deux": [d for d in attaques if par_filtre[d] and statut(d) == "detected"],
        "juge_seul": [d for d in attaques if not par_filtre[d] and statut(d) == "detected"],
        "filtre_seul": [d for d in attaques if par_filtre[d] and statut(d) != "detected"],
        "aucun": [d for d in attaques if not par_filtre[d] and statut(d) != "detected"],
    }

    detectes = [d for d in attaques if statut(d) == "detected"]
    faux_positifs = [d for d in normaux if statut(d) == "detected"]
    return {
        "documents": len(ordre),
        "attaques": {
            "total": len(attaques),
            "detectees": len(detectes),
            "taux_detection": taux(len(detectes), len(attaques)),
            "manquees": [(d, manifeste[d]["type_attaque"]) for d in attaques if statut(d) == "not_detected"],
            "indisponibles": [d for d in attaques if statut(d) == "unavailable"],
            "par_type_attaque": {k: v for k, v in sorted(par_attaque.items())},
        },
        "normaux": {
            "total": len(normaux),
            "faux_positifs": faux_positifs,
            "taux_faux_positifs": taux(len(faux_positifs), len(normaux)),
            "indisponibles": [d for d in normaux if statut(d) == "unavailable"],
        },
        "complementarite_filtre": complementarite,
        "types_renvoyes": dict(Counter(verdicts[d][1] for d in detectes if verdicts[d][1])),
        "verdicts": {d: list(v) for d, v in verdicts.items()},
    }


def rapport_markdown(r: dict) -> str:
    a, n, c = r["attaques"], r["normaux"], r["complementarite_filtre"]
    md = ["# Évaluation du juge d'injection LLM", "",
          f"{r['documents']} documents jugés ({a['total']} d'attaque, {n['total']} normaux).", "",
          "| Indicateur | Valeur |", "|---|---|",
          f"| Attaques détectées | {a['detectees']} / {a['total']} ({pct(a['taux_detection'])}) |",
          f"| Faux positifs (documents normaux signalés) | {len(n['faux_positifs'])} / {n['total']} ({pct(n['taux_faux_positifs'])}) |",
          f"| Juge indisponible (attaques / normaux) | {len(a['indisponibles'])} / {len(n['indisponibles'])} |",
          "", "## Par famille d'attaque", "", "| Famille | Détectées | Total | Indisponibles |", "|---|---|---|---|"]
    for famille, v in a["par_type_attaque"].items():
        md.append(f"| {famille} | {v['detectes']} | {v['total']} | {v['indisponibles']} |")
    md += ["", "Attaques manquées : " + (", ".join(f"{d} ({t})" for d, t in a["manquees"]) or "aucune"),
           "Faux positifs : " + (", ".join(n["faux_positifs"]) or "aucun"),
           "", "## Apport par rapport au filtre à motifs (F5), sur les documents d'attaque", "",
           "| | Documents |", "|---|---|",
           f"| Repérés par les deux | {len(c['les_deux'])} |",
           f"| Repérés par le juge seulement | {len(c['juge_seul'])} |",
           f"| Repérés par le filtre seulement | {len(c['filtre_seul'])} |",
           f"| Repérés par aucun des deux | {len(c['aucun'])} |", "",
           "Types d'injection renvoyés par le juge : "
           + (", ".join(f"{k} ({v})" for k, v in sorted(r["types_renvoyes"].items())) or "aucun"),
           "", "Rappel : « rien repéré » ne prouve pas qu'un document est sûr, le juge peut être trompé."]
    return "\n".join(md) + "\n"


def ecrire(resultats: dict, sortie: Path) -> str:
    sortie.mkdir(parents=True, exist_ok=True)
    (sortie / "metriques_juge.json").write_text(json.dumps(resultats, ensure_ascii=False, indent=2), encoding="utf-8")
    rapport = rapport_markdown(resultats)
    (sortie / "metriques_juge.md").write_text(rapport, encoding="utf-8")
    with open(sortie / "erreurs_juge.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["doc_id", "erreur", "detail"])
        for doc_id, type_attaque in resultats["attaques"]["manquees"]:
            w.writerow([doc_id, "attaque_manquee", type_attaque])
        for doc_id in resultats["normaux"]["faux_positifs"]:
            w.writerow([doc_id, "faux_positif", ""])
        for doc_id in resultats["attaques"]["indisponibles"] + resultats["normaux"]["indisponibles"]:
            w.writerow([doc_id, "juge_indisponible", ""])
    return rapport


async def lancer(corpus: Path, sortie: Path, concurrence: int) -> None:
    from anonymia.dependencies import build_injection_judge, build_llm_client

    juge = build_injection_judge(build_llm_client())
    try:
        resultats = await evaluer(corpus, juge, concurrence)
    finally:
        await juge.aclose()
    print(ecrire(resultats, sortie))


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus", type=Path, help="dossier corpus-test")
    parser.add_argument("--sortie", type=Path, default=Path("resultats_juge"))
    parser.add_argument("--concurrence", type=int, default=4, help="appels simultanés au LLM (4 par défaut)")
    args = parser.parse_args()
    asyncio.run(lancer(args.corpus, args.sortie, args.concurrence))


if __name__ == "__main__":
    main()
