import hashlib

import pytest

from anonymia.infrastructure.anonymization_strategy_factory import AnonymizationStrategyFactory
from anonymia.infrastructure.regex_detector import RegexDetector
from anonymia.service.business_objects.pii_span import PIISpan
from anonymia.service.detection_service import DetectionService
from anonymia.service.interfaces.pii_detector import PIIDetector
from tests.fakes import FakeArchiveRepository

CONTENT = "Écrire à jean@mail.fr pour le dossier."


class FailingDetector(PIIDetector):
    """Simule un LLM indisponible."""

    async def detect(self, content):
        raise RuntimeError("service indisponible")


class DuplicateDetector(PIIDetector):
    """Renvoie la même PII que le regex : les deux spans se chevauchent."""

    async def detect(self, content):
        start = content.index("jean@mail.fr")
        return [PIISpan("jean@mail.fr", "EMAIL", start, start + 12, "DuplicateDetector")]


class CountingDetector(PIIDetector):
    def __init__(self):
        self.calls = 0

    async def detect(self, content):
        self.calls += 1
        return []


class BrokenArchive(FakeArchiveRepository):
    async def save(self, entry):
        raise ConnectionError("base indisponible")


@pytest.fixture
def archive():
    return FakeArchiveRepository()


def make_service(archive, detectors=None):
    detectors = [RegexDetector()] if detectors is None else detectors
    return DetectionService(detectors, AnonymizationStrategyFactory(), archive)


# ---------------------------------------------------------------------------
# analyze : liste des PII, sans archivage
# ---------------------------------------------------------------------------


async def test_analyze_renvoie_les_pii_fusionnees(archive):
    service = make_service(archive, [RegexDetector(), DuplicateDetector()])

    spans = await service.analyze(CONTENT)

    assert len(spans) == 1  # le doublon est écarté
    assert spans[0].text == "jean@mail.fr"


async def test_analyze_n_archive_rien(archive):
    await make_service(archive).analyze(CONTENT)

    assert archive.entries == []


# ---------------------------------------------------------------------------
# detect : anonymisation + archivage
# ---------------------------------------------------------------------------


async def test_detect_anonymise_et_archive_une_entree(archive):
    result = await make_service(archive).detect(CONTENT, "masking", user_id=7)

    assert result == "Écrire à [EMAIL_1] pour le dossier."
    assert len(archive.entries) == 1
    entry = archive.entries[0]
    assert entry.user_id == 7
    assert entry.hash_document == hashlib.sha256(CONTENT.encode("utf-8")).hexdigest()
    assert entry.strategie_anonymisation == "masking"
    assert entry.detecteurs_contributeurs == "RegexDetector"
    assert entry.nb_pii_detectees == 1
    assert entry.date_traitement.tzinfo is not None


async def test_l_entree_d_audit_ne_contient_ni_le_document_ni_les_pii(archive):
    await make_service(archive).detect(CONTENT, "masking", user_id=1)

    for value in vars(archive.entries[0]).values():
        assert "jean@mail.fr" not in str(value)
        assert "dossier" not in str(value)


async def test_document_sans_pii_est_archive_avec_zero(archive):
    result = await make_service(archive).detect("Rien à signaler.", "masking", user_id=1)

    assert result == "Rien à signaler."
    assert archive.entries[0].nb_pii_detectees == 0
    assert archive.entries[0].detecteurs_contributeurs == "RegexDetector"


async def test_mode_degrade_le_detecteur_en_panne_n_est_pas_liste(archive):
    service = make_service(archive, [FailingDetector(), RegexDetector()])

    result = await service.detect(CONTENT, "masking", user_id=1)

    assert "[EMAIL_1]" in result  # le regex a fait son travail
    assert archive.entries[0].detecteurs_contributeurs == "RegexDetector"


async def test_strategie_inconnue_echoue_sans_appeler_les_detecteurs(archive):
    spy = CountingDetector()

    with pytest.raises(ValueError):
        await make_service(archive, [spy]).detect(CONTENT, "magie", user_id=1)

    assert spy.calls == 0
    assert archive.entries == []


async def test_un_echec_d_archivage_n_est_pas_masque():
    service = DetectionService([RegexDetector()], AnonymizationStrategyFactory(), BrokenArchive())

    with pytest.raises(ConnectionError):
        await service.detect(CONTENT, "masking", user_id=1)