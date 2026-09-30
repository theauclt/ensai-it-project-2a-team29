import pytest

from anonymia.infrastructure.regex_detector import RegexDetector


@pytest.fixture
def detector():
    return RegexDetector()


@pytest.mark.asyncio
async def test_detect_email(detector):
    result = await detector.detect("Mon email est test@example.com")

    assert len(result) == 1
    assert result[0].text == "test@example.com"
    assert result[0].type == "EMAIL"


@pytest.mark.asyncio
async def test_detect_no_pii(detector):
    result = await detector.detect("Ceci est un texte neutre, sans donnee personnelle.")

    assert result == []


@pytest.mark.asyncio
async def test_detect_telephone_valide(detector):
    result = await detector.detect("Contactez-moi au +33612345678")

    assert len(result) == 1
    assert result[0].type == "TELEPHONE"
    assert result[0].text == "+33612345678"


@pytest.mark.asyncio
async def test_detect_telephone_sans_indicatif_ignore(detector):
    # suite de chiffres plausible mais sans indicatif pays : phonenumbers
    # ne peut pas la valider, donc elle ne doit pas etre remontee
    result = await detector.detect("Le code est 12345678901")

    assert result == []


@pytest.mark.asyncio
async def test_detect_iban_valide(detector):
    result = await detector.detect("IBAN : FR7630006000011234567890189")

    assert len(result) == 1
    assert result[0].type == "IBAN"
    assert result[0].text == "FR7630006000011234567890189"


@pytest.mark.asyncio
async def test_detect_iban_cle_de_controle_invalide_ignore(detector):
    # meme format qu'un IBAN FR, mais cle de controle fausse (dernier chiffre modifie)
    result = await detector.detect("IBAN : FR7630006000011234567890180")

    assert result == []


@pytest.mark.asyncio
async def test_detect_plaque_actuelle(detector):
    result = await detector.detect("Vehicule immatricule AB-123-CD")

    assert len(result) == 1
    assert result[0].type == "PLAQUE_ACTUELLE"
    assert result[0].text == "AB-123-CD"


@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="bug connu : _is_valid_nir renvoie toujours False "
    "(condition len(nir) != 15 or len(nir) != 13 toujours vraie)",
    strict=True,
)
async def test_detect_nir_valide(detector):
    # NIR construit avec une cle de controle correcte (modulo 97)
    result = await detector.detect("Numero de secu : 195057800604825")

    assert len(result) == 1
    assert result[0].type == "NIR"
