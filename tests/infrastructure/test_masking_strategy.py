from anonymia.infrastructure.masking_strategy import MaskingStrategy
from anonymia.service.business_objects.pii_span import PIISpan



######### EMAIL

def test_mask_email():
    content = "Mon adresse est test@gmail.com."
    email = "test@gmail.com"

    start = content.index(email)

    span = PIISpan(
        text=email,
        type="EMAIL",
        start=start,
        end=start + len(email),
        source_detector="regex"
    )

    result = MaskingStrategy().apply(content, [span])

    assert result == "Mon adresse est [EMAIL_1]."
#------------------------------------------------------------------------------------------------------
# TEL
#------------------------------------------------------------------------------------------------------


def test_mask_telephone(): 
    content = "Appelez-moi au 06 12 34 56 78."
    telephone = "06 12 34 56 78"

    start = content.index(telephone)

    span = PIISpan(
        text=telephone,
        type="TELEPHONE",
        start=start,
        end=start + len(telephone),
        source_detector="regex"
    )

    result = MaskingStrategy().apply(content, [span])

    assert result == "Appelez-moi au [TEL_1]."


#------------------------------------------------------------------------------------------------------
# NIR
#------------------------------------------------------------------------------------------------------

def test_mask_nir():
    content = "Mon numéro de sécurité sociale est 189057512345678."
    nir = "189057512345678"

    start = content.index(nir)

    span = PIISpan(
        text=nir,
        type="NIR",
        start=start,
        end=start + len(nir),
        source_detector="regex"
    )

    result = MaskingStrategy().apply(content, [span])

    assert result == "Mon numéro de sécurité sociale est [NIR_1]."


#------------------------------------------------------------------------------------------------------
# IBAN
#------------------------------------------------------------------------------------------------------

def test_mask_iban():
    content = "Mon IBAN est FR76 3000 6000 0112 3456 7890 189."
    iban = "FR76 3000 6000 0112 3456 7890 189"

    start = content.index(iban)

    span = PIISpan(
        text=iban,
        type="IBAN",
        start=start,
        end=start + len(iban),
        source_detector="regex"
    )

    result = MaskingStrategy().apply(content, [span])

    assert result == "Mon IBAN est [IBAN_1]."


#------------------------------------------------------------------------------------------------------
# PLAQUE ACTUELLE
#------------------------------------------------------------------------------------------------------

def test_mask_plaque_actuelle():
    content = "La voiture porte la plaque AB-123-CD."
    plaque = "AB-123-CD"

    start = content.index(plaque)

    span = PIISpan(
        text=plaque,
        type="PLAQUE_ACTUELLE",
        start=start,
        end=start + len(plaque),
        source_detector="regex"
    )

    result = MaskingStrategy().apply(content, [span])

    assert result == "La voiture porte la plaque [PLAQUE_1]."


#------------------------------------------------------------------------------------------------------
# PLAQUE ANCIENNE
#------------------------------------------------------------------------------------------------------

def test_mask_plaque_ancienne():
    content = "L'ancienne immatriculation est 1234 AB 35."
    plaque = "1234 AB 35"

    start = content.index(plaque)

    span = PIISpan(
        text=plaque,
        type="PLAQUE_ANCIENNE",
        start=start,
        end=start + len(plaque),
        source_detector="regex"
    )

    result = MaskingStrategy().apply(content, [span])

    assert result == "L'ancienne immatriculation est [PLAQUE_1]."


#------------------------------------------------------------------------------------------------------
# PLAQUE DIPLOMATIQUE
#------------------------------------------------------------------------------------------------------

def test_mask_plaque_diplomatique():
    content = "Le véhicule diplomatique porte la plaque 123 CD 456."
    plaque = "123 CD 456"

    start = content.index(plaque)

    span = PIISpan(
        text=plaque,
        type="PLAQUE_DIPLOMATIQUE",
        start=start,
        end=start + len(plaque),
        source_detector="regex"
    )

    result = MaskingStrategy().apply(content, [span])

    assert result == "Le véhicule diplomatique porte la plaque [PLAQUE_1]."



#------------------------------------------------------------------------------------------------------
# PLUSIEURS PII DU MÊME TYPE
#------------------------------------------------------------------------------------------------------

def test_mask_plusieurs_emails():
    content = "Contactez a@gmail.com ou b@gmail.com."
    emails = ["a@gmail.com", "b@gmail.com"]

    spans = []
    for email in emails:
        start = content.index(email)
        spans.append(PIISpan(
            text=email,
            type="EMAIL",
            start=start,
            end=start + len(email),
            source_detector="regex"
        ))

    result = MaskingStrategy().apply(content, spans)

    assert result == "Contactez [EMAIL_1] ou [EMAIL_2]."


#------------------------------------------------------------------------------------------------------
# MÊME PII RÉPÉTÉE
#------------------------------------------------------------------------------------------------------

def test_mask_email_repete():
    content = "Écrivez à test@gmail.com puis à test@gmail.com."
    email = "test@gmail.com"

    start1 = content.index(email)
    start2 = content.index(email, start1 + len(email))

    spans = [
        PIISpan(email, "EMAIL", start1, start1 + len(email), "regex"),
        PIISpan(email, "EMAIL", start2, start2 + len(email), "regex")
    ]

    result = MaskingStrategy().apply(content, spans)

    assert result == "Écrivez à [EMAIL_1] puis à [EMAIL_1]."


#------------------------------------------------------------------------------------------------------
# PLUSIEURS TYPES DE PII
#------------------------------------------------------------------------------------------------------

def test_mask_plusieurs_types():
    content = "Mail : a@gmail.com, téléphone : 06 12 34 56 78, autre mail : b@gmail.com."

    pii = [
        ("a@gmail.com", "EMAIL"),
        ("06 12 34 56 78", "TELEPHONE"),
        ("b@gmail.com", "EMAIL")
    ]

    spans = []
    for valeur, type_pii in pii:
        start = content.index(valeur)
        spans.append(PIISpan(
            text=valeur,
            type=type_pii,
            start=start,
            end=start + len(valeur),
            source_detector="regex"
        ))

    result = MaskingStrategy().apply(content, spans)

    assert result == "Mail : [EMAIL_1], téléphone : [TEL_1], autre mail : [EMAIL_2]."


#------------------------------------------------------------------------------------------------------
# COMPTEUR COMMUN AUX PLAQUES
#------------------------------------------------------------------------------------------------------

def test_mask_plusieurs_types_plaques():
    content = "Plaques : AB-123-CD, 1234 AB 35 et 123 CD 456."

    plaques = [
        ("AB-123-CD", "PLAQUE_ACTUELLE"),
        ("1234 AB 35", "PLAQUE_ANCIENNE"),
        ("123 CD 456", "PLAQUE_DIPLOMATIQUE")
    ]

    spans = []
    for plaque, type_pii in plaques:
        start = content.index(plaque)
        spans.append(PIISpan(
            text=plaque,
            type=type_pii,
            start=start,
            end=start + len(plaque),
            source_detector="regex"
        ))

    result = MaskingStrategy().apply(content, spans)

    assert result == "Plaques : [PLAQUE_1], [PLAQUE_2] et [PLAQUE_3]."


#------------------------------------------------------------------------------------------------------
# CONSERVATION DU TEXTE
#------------------------------------------------------------------------------------------------------

def test_mask_conservation_texte():
    content = "Bonjour ! Mon mail est test@gmail.com, merci de me répondre."
    email = "test@gmail.com"

    start = content.index(email)

    span = PIISpan(
        text=email,
        type="EMAIL",
        start=start,
        end=start + len(email),
        source_detector="regex"
    )

    result = MaskingStrategy().apply(content, [span])

    assert result == "Bonjour ! Mon mail est [EMAIL_1], merci de me répondre."


#------------------------------------------------------------------------------------------------------
# AUCUNE PII
#------------------------------------------------------------------------------------------------------

def test_mask_aucune_pii():
    content = "Bonjour, ce document ne contient aucune PII."

    result = MaskingStrategy().apply(content, [])

    assert result == content


#------------------------------------------------------------------------------------------------------
# CONSERVATION DES POSITIONS
#------------------------------------------------------------------------------------------------------

def test_mask_positions():
    content = "a@gmail.com et b@gmail.com sont deux adresses."
    emails = ["a@gmail.com", "b@gmail.com"]

    spans = []
    for email in emails:
        start = content.index(email)
        spans.append(PIISpan(
            text=email,
            type="EMAIL",
            start=start,
            end=start + len(email),
            source_detector="regex"
        ))

    result = MaskingStrategy().apply(content, spans)

    assert result == "[EMAIL_1] et [EMAIL_2] sont deux adresses."


#------------------------------------------------------------------------------------------------------
# SPANS DANS LE DÉSORDRE
#------------------------------------------------------------------------------------------------------

def test_mask_spans_desordonnes():
    content = "Premier : a@gmail.com, deuxième : b@gmail.com."
    email1 = "a@gmail.com"
    email2 = "b@gmail.com"

    start1 = content.index(email1)
    start2 = content.index(email2)

    span1 = PIISpan(email1, "EMAIL", start1, start1 + len(email1), "regex")
    span2 = PIISpan(email2, "EMAIL", start2, start2 + len(email2), "regex")

    # On fournit volontairement les spans dans le mauvais ordre
    result = MaskingStrategy().apply(content, [span2, span1])

    assert result == "Premier : [EMAIL_1], deuxième : [EMAIL_2]."

