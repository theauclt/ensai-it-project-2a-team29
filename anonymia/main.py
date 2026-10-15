import asyncio
from pathlib import Path

from infrastructure.anonymization_strategy_factory import AnonymizationStrategyFactory
from infrastructure.regex_detector import RegexDetector
from service.detection_service import DetectionService

corpus_dir = Path(
    "/home/onyxia/work/ensai-it-project-2a-team29/corpus-test/documents"
)

detectors = [RegexDetector()]
strategy_factory = AnonymizationStrategyFactory()

detection_service = DetectionService(
    detectors=detectors,
    strategy_factory=strategy_factory,
)

for i in range(1, 16):
    fichier = corpus_dir / f"doc_{i:03d}.txt"

    print(f"\n{'=' * 50}")
    print(f"Document : {fichier.name}")
    print("=" * 50)

    if not fichier.exists():
        print("Fichier introuvable !")
        continue

    text = fichier.read_text(encoding="utf-8")

    resultat = asyncio.run(
        detection_service.detect(text, "masking")
    )

    print(resultat)