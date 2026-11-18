"""Mesure le temps de détection des regex et du LLM.

À lancer depuis la racine du projet (là où se trouve le dossier anonymia/) :
    python mesurer_temps.py                         # regex seulement
    python mesurer_temps.py --llm                   # regex + LLM (variables LLM_* du .env)
    python mesurer_temps.py --llm --timeout 60      # laisse 60 s au LLM pour répondre
    python mesurer_temps.py --llm --court --essais 5
"""
import argparse
import asyncio
import os
import statistics
import time

from anonymia.infrastructure.regex_detector import RegexDetector

PHRASES = (
    "Bonjour, je suis Marie Durand (marie.durand@mail.fr), née le 12/03/1985. "
    "Appelez-moi au 06 12 34 56 78. Mon NIR est 2 85 03 75 116 001 23 et mon IBAN "
    "FR7630006000011234567890189. J'habite 12 rue des Lilas, 75011 Paris. "
)


async def chronometrer(detecteur, texte, essais):
    """Renvoie (durées des essais réussis, nombre d'échecs, nombre de PII, dernière erreur)."""
    durees, echecs, nb, derniere = [], 0, 0, None
    for _ in range(essais):
        debut = time.perf_counter()
        try:
            nb = len(await detecteur.detect(texte))
        except Exception as exc:  # noqa: BLE001 : on veut compter les pannes, pas planter
            echecs += 1
            derniere = f"{type(exc).__name__}: {exc}"
            print(f"  essai en échec après {time.perf_counter() - debut:.1f} s ({derniere})")
        else:
            durees.append(time.perf_counter() - debut)
    return durees, echecs, nb, derniere


def resume(nom, durees, echecs, nb):
    total = len(durees) + echecs
    if not durees:
        print(f"{nom:6s} aucun essai réussi sur {total}")
        return
    durees = sorted(durees)
    p95 = durees[max(0, int(len(durees) * 0.95) - 1)]
    print(
        f"{nom:6s} médiane {statistics.median(durees) * 1000:9.1f} ms | "
        f"p95 {p95 * 1000:9.1f} ms | min {durees[0] * 1000:9.1f} ms | "
        f"max {durees[-1] * 1000:9.1f} ms | {nb} PII | "
        f"{len(durees)} réussis, {echecs} échecs sur {total}"
    )


async def main(args):
    texte = PHRASES * (1 if args.court else 5)  # ~220 ou ~1 100 caractères
    print(f"Texte de {len(texte)} caractères\n")
    durees, echecs, nb, _ = await chronometrer(RegexDetector(), texte, 200)
    resume("Regex", durees, echecs, nb)

    if args.llm:
        if args.timeout:
            os.environ["LLM_TIMEOUT"] = str(args.timeout)
        from anonymia.dependencies import build_llm_detector

        print(f"\nLLM : modèle {os.getenv('LLM_MODEL')}, délai {os.getenv('LLM_TIMEOUT')} s")
        llm = build_llm_detector()
        try:
            print("Appel d'échauffement (non compté)...")
            await chronometrer(llm, texte, 1)
            durees, echecs, nb, _ = await chronometrer(llm, texte, args.essais)
            resume("LLM", durees, echecs, nb)
        finally:
            await llm.aclose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm", action="store_true")
    parser.add_argument("--timeout", type=float, help="délai en secondes (sinon LLM_TIMEOUT)")
    parser.add_argument("--essais", type=int, default=10)
    parser.add_argument("--court", action="store_true", help="texte de ~220 caractères")
    asyncio.run(main(parser.parse_args()))