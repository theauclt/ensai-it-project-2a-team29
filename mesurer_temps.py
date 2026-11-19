"""Mesure le temps de détection des regex et du LLM.

À lancer depuis la racine du projet (là où se trouve le dossier anonymia/) :
    python mesurer_temps.py                    # regex seulement
    python mesurer_temps.py --llm              # regex + LLM (variables LLM_* du .env)
    python mesurer_temps.py --llm --timeout 30 # laisse 30 s au LLM pour répondre

Le script s'arrête dès que le LLM échoue (pas d'attente répétée).
"""
import argparse
import asyncio
import os
import statistics
import time

from anonymia.infrastructure.regex_detector import RegexDetector

TEXTE = "Marie Durand habite à Nantes, son mail est marie.durand@mail.fr."


def resume(nom, durees):
    durees = sorted(durees)
    p95 = durees[max(0, int(len(durees) * 0.95) - 1)]
    print(
        f"{nom:6s} médiane {statistics.median(durees) * 1000:9.1f} ms | "
        f"p95 {p95 * 1000:9.1f} ms | min {durees[0] * 1000:9.1f} ms | "
        f"max {durees[-1] * 1000:9.1f} ms | {len(durees)} essais"
    )


async def mesurer_regex():
    detecteur, durees = RegexDetector(), []
    for _ in range(200):
        debut = time.perf_counter()
        nb = len(await detecteur.detect(TEXTE))
        durees.append(time.perf_counter() - debut)
    print(f"{nb} PII trouvées par les regex")
    resume("Regex", durees)


async def sonder(client, modele):
    """Requête minimale : sépare 'le service ne répond pas' de 'la génération est lente'."""
    debut = time.perf_counter()
    try:
        r = await client.post(
            "/chat/completions",
            json={"model": modele, "max_tokens": 5,
                  "messages": [{"role": "user", "content": "Réponds : OK"}]},
        )
    except Exception as exc:  # noqa: BLE001
        print(f"  sonde en échec après {time.perf_counter() - debut:.1f} s : "
              f"{type(exc).__name__}: {exc}")
        return False
    print(f"  sonde : HTTP {r.status_code} en {time.perf_counter() - debut:.1f} s")
    if r.status_code != 200:
        print(f"  réponse : {r.text[:300]}")
    return r.status_code == 200


async def mesurer_llm(timeout, essais):
    if timeout:
        os.environ["LLM_TIMEOUT"] = str(timeout)
    from anonymia.dependencies import build_llm_client, build_llm_detector

    modele = os.getenv("LLM_MODEL", "qwen3-8-27b")
    print(f"\nLLM : {os.getenv('LLM_BASE_URL', '(URL par défaut)')} | modèle {modele} "
          f"| délai {os.getenv('LLM_TIMEOUT', '60')} s")
    client = build_llm_client()
    detecteur = build_llm_detector(client)
    try:
        print("1) Sonde minimale (5 jetons) :")
        if not await sonder(client, modele):
            print("-> le service ne répond pas correctement : le problème n'est pas la détection.")
            return
        print("2) Détection complète :")
        durees = []
        for i in range(essais):
            debut = time.perf_counter()
            try:
                nb = len(await detecteur.detect(TEXTE))
            except Exception as exc:  # noqa: BLE001
                print(f"  essai {i + 1} en échec après {time.perf_counter() - debut:.1f} s : "
                      f"{type(exc).__name__}: {exc}")
                break
            durees.append(time.perf_counter() - debut)
            print(f"  essai {i + 1} : {durees[-1]:.1f} s ({nb} PII)")
        if durees:
            resume("LLM", durees)
    finally:
        await detecteur.aclose()


async def main(args):
    await mesurer_regex()
    if args.llm:
        await mesurer_llm(args.timeout, args.essais)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm", action="store_true")
    parser.add_argument("--timeout", type=float, help="délai en secondes (sinon LLM_TIMEOUT)")
    parser.add_argument("--essais", type=int, default=3)
    asyncio.run(main(parser.parse_args()))