import phonenumbers
import pytest
 
from anonymia.infrastructure.regex_detector import RegexDetector
 
# Marqueur pour les tests bloques par un bug connu de
# RegexDetector._is_valid_phonenumber : phonenumbers.parse(numero, None) leve une
# NumberParseException pour tout candidat sans "+", ce qui fait planter detect()
# en entier (meme pour un IBAN ou un NIR dont les chiffres ressemblent a un telephone).
# Correctif attendu : try/except NumberParseException -> False (et/ou region "FR").
# strict=True : quand le bug est corrige, le test "passe" => pytest le signale,
# il suffit alors de retirer le marqueur.
bug_phonenumber = pytest.mark.xfail(
    reason="bug connu : _is_valid_phonenumber leve NumberParseException "
    "pour tout candidat sans indicatif '+' (parse(..., None))",
    raises=phonenumbers.NumberParseException,
    strict=True,
)
 

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

# ---------------------------------------------------------------------------
# Cas generaux
# ---------------------------------------------------------------------------
 
 
@pytest.mark.asyncio
async def test_detect_contenu_vide(detector):
    result = await detector.detect("")
 
    assert result == []
 
 
@pytest.mark.asyncio
async def test_detect_chiffres_non_pii_ignores(detector):
    # date, heure et petit nombre : aucun ne doit etre pris pour une PII
    result = await detector.detect("Le 12 mars 2020, rdv a 10 h 30, ref 12345")
 
    assert result == []
 
 
@pytest.mark.asyncio
async def test_detect_plusieurs_types_dans_un_texte(detector):
    content = (
        "Contact : marie@free.fr, +33 6 12 34 56 78, "
        "IBAN FR7630006000011234567890189, vehicule AB-123-CD"
    )
 
    result = await detector.detect(content)
 
    assert {span.type for span in result} == {
        "EMAIL",
        "TELEPHONE",
        "IBAN",
        "PLAQUE_ACTUELLE",
    }
    # chaque span doit pointer exactement sur son texte dans le document
    for span in result:
        assert content[span.start:span.end] == span.text
        assert span.source_detector == "RegexDetector"
 
 
# ---------------------------------------------------------------------------
# EMAIL
# ---------------------------------------------------------------------------
 
 
@pytest.mark.asyncio
async def test_detect_email_caracteres_speciaux(detector):
    # point, plus et tiret sont autorises dans la partie locale et dans le domaine
    result = await detector.detect("Ecrire a jean.dupont+admin@mail-server.fr svp")
 
    assert len(result) == 1
    assert result[0].type == "EMAIL"
    assert result[0].text == "jean.dupont+admin@mail-server.fr"
 
 
@pytest.mark.asyncio
async def test_detect_plusieurs_emails(detector):
    result = await detector.detect("De : marie@free.fr, a : paul@orange.fr")
 
    assert [span.text for span in result] == ["marie@free.fr", "paul@orange.fr"]
    assert all(span.type == "EMAIL" for span in result)
 
 
@pytest.mark.asyncio
async def test_detect_meme_email_deux_fois(detector):
    # chaque occurrence doit etre remontee avec sa propre position
    # (la strategie de pseudonymisation s'appuie dessus)
    content = "marie@free.fr puis encore marie@free.fr"
 
    result = await detector.detect(content)
 
    assert len(result) == 2
    assert result[0].start != result[1].start
    for span in result:
        assert content[span.start:span.end] == "marie@free.fr"
 
 
@pytest.mark.asyncio
async def test_detect_email_positions_et_source(detector):
    content = "Mon email est test@example.com"
 
    result = await detector.detect(content)
 
    assert len(result) == 1
    assert result[0].start == content.index("test@example.com")
    assert result[0].end == len(content)
    assert result[0].source_detector == "RegexDetector"
 
 
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "texte",
    [
        "Contact : test@",
        "Contact : @example.com",
        "Contact : test@example",
    ],
)
async def test_detect_email_incomplet_ignore(detector, texte):
    result = await detector.detect(texte)
 
    assert result == []
 
 
@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="bug connu : le [\\w.-]+ final du regex EMAIL avale le point "
    "qui termine la phrase (renvoie 'test@example.com.')",
    strict=True,
)
async def test_detect_email_point_final_exclu(detector):
    result = await detector.detect("Ecrivez a test@example.com.")
 
    assert len(result) == 1
    assert result[0].text == "test@example.com"
 
 
# ---------------------------------------------------------------------------
# TELEPHONE
# ---------------------------------------------------------------------------
 
 
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "numero",
    [
        "+33 6 12 34 56 78",
        "+33 1 23 45 67 89",
        "+44 20 7946 0958",
        "+49 30 901820",
        "+1 202 555 0123",
    ],
)
async def test_detect_telephone_international_avec_espaces(detector, numero):
    result = await detector.detect(f"Appelez le {numero} demain")
 
    assert len(result) == 1
    assert result[0].type == "TELEPHONE"
    assert result[0].text == numero
 
 
@pytest.mark.asyncio
async def test_detect_telephone_invalide_ignore(detector):
    # format plausible pour le regex (10 chiffres, avec indicatif) mais numero
    # francais trop court : rejete par phonenumbers
    result = await detector.detect("Appelez le +33 6 12 34 56 7")
 
    assert result == []
 
 
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "numero",
    [
        "06 12 34 56 78",
        "06.12.34.56.78",
        "06-12-34-56-78",
        "0612345678",
        "0033 6 12 34 56 78",
    ],
)
@pytest.mark.xfail(
    reason="bug connu : les formats francais sans '+' (cf. Detection PII) "
    "ne sont jamais valides car parse(..., None) n'a pas de region par defaut "
    "(utiliser la region 'FR')",
    strict=True,
)
async def test_detect_telephone_francais_national(detector, numero):
    result = await detector.detect(f"Mon numero : {numero}")
 
    assert len(result) == 1
    assert result[0].type == "TELEPHONE"
    assert result[0].text == numero
 
 
@pytest.mark.asyncio
@bug_phonenumber
async def test_detect_date_numerique_ne_plante_pas(detector):
    # 8 chiffres : candidat pour le regex TELEPHONE, rejete par phonenumbers
    result = await detector.detect("Reference du dossier : 20200312")
 
    assert result == []
 
 
# ---------------------------------------------------------------------------
# IBAN
# ---------------------------------------------------------------------------
 
 
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "iban",
    [
        "DE89370400440532013000",
        "ES9121000418450200051332",
        "IT60X0542811101000000123456",
    ],
)
async def test_detect_iban_autres_pays_valides(detector, iban):
    result = await detector.detect(f"IBAN : {iban}")
 
    assert len(result) == 1
    assert result[0].type == "IBAN"
    assert result[0].text == iban
 
 
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "iban",
    [
        "BE68539007547034",
        "NL91ABNA0417164300",
        "GB82WEST12345698765432",
    ],
)
@bug_phonenumber
async def test_detect_iban_avec_longue_suite_de_chiffres(detector, iban):
    # la partie numerique (8 a 15 chiffres consecutifs) est aussi candidate
    # pour le regex TELEPHONE : elle ne doit pas faire planter detect()
    result = await detector.detect(f"IBAN : {iban}")
 
    assert len(result) == 1
    assert result[0].type == "IBAN"
    assert result[0].text == iban
 
 
@pytest.mark.asyncio
async def test_detect_iban_pays_inconnu_ignore(detector):
    # "XX" n'est pas dans IBAN_LENGTHS
    result = await detector.detect("IBAN : XX7630006000011234567890189")
 
    assert result == []
 
 
@pytest.mark.asyncio
async def test_detect_iban_longueur_incorrecte_ignore(detector):
    # un IBAN FR doit faire 27 caracteres, pas 19
    result = await detector.detect("IBAN : FR76300060000112345")
 
    assert result == []
 
 
@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="bug connu : le regex IBAN ne capte pas les IBAN ecrits avec des "
    "espaces, alors que _is_valid_iban sait les normaliser",
    strict=True,
)
async def test_detect_iban_avec_espaces(detector):
    result = await detector.detect(
        "IBAN : FR76 3000 6000 0112 3456 7890 189 pour le virement"
    )
 
    assert len(result) == 1
    assert result[0].type == "IBAN"
    assert result[0].text == "FR76 3000 6000 0112 3456 7890 189"
 
 
# ---------------------------------------------------------------------------
# NIR
# ---------------------------------------------------------------------------
 
 
@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="bugs connus : (1) le regex NIR est ancre par ^...$ donc ne trouve "
    "rien au milieu d'une phrase, (2) il ne capte pas la cle (13 chiffres "
    "seulement), (3) _is_valid_nir renvoie toujours False, (4) le NIR est aussi "
    "candidat TELEPHONE et plante via _is_valid_phonenumber",
    strict=True,
)
async def test_detect_nir_valide_avec_espaces(detector):
    result = await detector.detect("Numero de secu : 1 95 05 78 006 048 25")
 
    assert len(result) == 1
    assert result[0].type == "NIR"
    assert result[0].text == "1 95 05 78 006 048 25"
 
 
@pytest.mark.asyncio
@bug_phonenumber
async def test_detect_nir_cle_de_controle_invalide_ignore(detector):
    # meme NIR que test_detect_nir_valide mais cle 26 au lieu de 25
    result = await detector.detect("Numero de secu : 195057800604826")
 
    assert result == []
 
 
@pytest.mark.asyncio
@bug_phonenumber
async def test_detect_nir_mois_invalide_ignore(detector):
    # mois 13 : impossible dans un NIR
    result = await detector.detect("Numero de secu : 195137800604825")
 
    assert result == []
 
 
# ---------------------------------------------------------------------------
# PLAQUES D'IMMATRICULATION
# ---------------------------------------------------------------------------
 
 
@pytest.mark.asyncio
async def test_detect_plusieurs_plaques_actuelles(detector):
    result = await detector.detect("Vehicules AB-123-CD et EF-456-GH")
 
    assert [span.text for span in result] == ["AB-123-CD", "EF-456-GH"]
    assert all(span.type == "PLAQUE_ACTUELLE" for span in result)
 
 
@pytest.mark.asyncio
@pytest.mark.parametrize("plaque", ["AB 123 CD", "AB123CD"])
@pytest.mark.xfail(
    reason="ecart avec Detection PII : le regex PLAQUE_ACTUELLE n'accepte que "
    "le format avec tirets (prevu : [\\s-]? entre les groupes)",
    strict=True,
)
async def test_detect_plaque_actuelle_autres_ecritures(detector, plaque):
    result = await detector.detect(f"Vehicule immatricule {plaque}")
 
    assert len(result) == 1
    assert result[0].type == "PLAQUE_ACTUELLE"
    assert result[0].text == plaque
 
 
@pytest.mark.asyncio
@pytest.mark.parametrize("plaque", ["1234 AB 75", "123 ABC 75"])
async def test_detect_plaque_ancienne(detector, plaque):
    result = await detector.detect(f"Vehicule immatricule {plaque}")
 
    assert len(result) == 1
    assert result[0].type == "PLAQUE_ANCIENNE"
    assert result[0].text == plaque
 
 
@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="ecart avec Detection PII : le departement 2A/2B (Corse) n'est "
    "pas gere par le regex PLAQUE_ANCIENNE",
    strict=True,
)
async def test_detect_plaque_ancienne_corse(detector):
    result = await detector.detect("Vehicule immatricule 12 AB 2A")
 
    assert len(result) == 1
    assert result[0].type == "PLAQUE_ANCIENNE"
    assert result[0].text == "12 AB 2A"
 
 
@pytest.mark.asyncio
async def test_detect_plaque_diplomatique(detector):
    result = await detector.detect("Vehicule immatricule 12 K 345.67 X")
 
    assert len(result) == 1
    assert result[0].type == "PLAQUE_DIPLOMATIQUE"
    assert result[0].text == "12 K 345.67 X"
 
 
@pytest.mark.asyncio
async def test_detect_plaque_diplomatique_avec_prefixe(detector):
    result = await detector.detect("Vehicule immatricule U 123 CMD 45")
 
    diplomatiques = [span for span in result if span.type == "PLAQUE_DIPLOMATIQUE"]
    assert len(diplomatiques) == 1
    assert diplomatiques[0].text == "U 123 CMD 45"
 
 
@pytest.mark.asyncio
async def test_detect_plaque_diplomatique_chevauche_plaque_ancienne(detector):
    # test de caracterisation : "123 CD 45" correspond aux deux regex.
    # RegexDetector ne dedoublonne pas, il remonte donc deux spans qui se
    # chevauchent. C'est a la fusion (DetectionService) de trancher : si le
    # detecteur est modifie pour dedoublonner, adapter ce test.
    result = await detector.detect("Vehicule immatricule 123 CD 45")
 
    assert {span.type for span in result} == {
        "PLAQUE_ANCIENNE",
        "PLAQUE_DIPLOMATIQUE",
    }
    assert {(span.start, span.end) for span in result} == {(21, 30)}
 
