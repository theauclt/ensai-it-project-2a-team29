"""
Test de fumée : envoie un petit texte au vrai LLM et affiche ce qui est détecté.

Usage (depuis la racine du dépôt) :
    export LLM_BASE_URL=http://localhost:11434/v1   # ou l'URL SSPCloud
    export LLM_MODEL=qwen2.5:3b
    export LLM_API_KEY=...                          # inutile pour Ollama
    python -m scripts.smoke_llm
"""

#ATTENTION ne pas renvoyer directement positions, passer par un match !!!

import asyncio

from anonymia.dependencies import build_llm_detector

TEXTE = (
    "Madame Claire Martin, née le 12 mars 1985 à Nantes, directrice des ressources "
    "humaines de la société Durand SA, habite 12 rue des Lilas à Rennes. "
    "Son frère Paul souhaite la contacter."
)


async def main() -> None:
    detector = build_llm_detector()
    try:
        spans = await detector.detect(TEXTE)
    finally:
        await detector.aclose()

    if not spans:
        print("Aucune PII détectée.")
    for span in spans:
        print(f"{span.type:<15} [{span.start:>3}:{span.end:<3}] {span.text!r}")


if __name__ == "__main__":
    asyncio.run(main())
