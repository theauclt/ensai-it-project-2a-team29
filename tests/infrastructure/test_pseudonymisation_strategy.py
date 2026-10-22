import pytest

from anonymia.infrastructure.pseudonymization_strategy import PseudonymizationStrategy
from anonymia.service.business_objects.pii_span import PIISpan


#------------------------------------------------------------------------------------------------------
# EMAIL
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_email():
    content = "Mon adresse est test@gmail.com."
    email = "test@gmail.com"
    start = content.index(email)

    span = PIISpan(email, "EMAIL", start, start + len(email), "regex")

    result = PseudonymizationStrategy().apply(content, [span])

    assert result == "Mon adresse est utilisateur1@example.com."


#------------------------------------------------------------------------------------------------------
# TELEPHONE
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_telephone():
    content = "Appelez-moi au 06 12 34 56 78."
    telephone = "06 12 34 56 78"
    start = content.index(telephone)

    span = PIISpan(telephone, "TELEPHONE", start, start + len(telephone), "regex")

    result = PseudonymizationStrategy().apply(content, [span])

    assert result == "Appelez-moi au 06 00 00 00 01."


#------------------------------------------------------------------------------------------------------
# PLAQUE ACTUELLE
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_plaque_actuelle():
    content = "La plaque est AB-123-CD."
    plaque = "AB-123-CD"
    start = content.index(plaque)

    span = PIISpan(plaque, "PLAQUE_ACTUELLE", start, start + len(plaque), "regex")

    result = PseudonymizationStrategy().apply(content, [span])

    assert result == "La plaque est XX-001-XX."


#------------------------------------------------------------------------------------------------------
# PLAQUE ANCIENNE
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_plaque_ancienne():
    content = "La plaque est 1234 AB 35."
    plaque = "1234 AB 35"
    start = content.index(plaque)

    span = PIISpan(plaque, "PLAQUE_ANCIENNE", start, start + len(plaque), "regex")

    result = PseudonymizationStrategy().apply(content, [span])

    assert result == "La plaque est XX-001-XX."


#------------------------------------------------------------------------------------------------------
# PLAQUE DIPLOMATIQUE
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_plaque_diplomatique():
    content = "La plaque est 123 CD 456."
    plaque = "123 CD 456"
    start = content.index(plaque)

    span = PIISpan(plaque, "PLAQUE_DIPLOMATIQUE", start, start + len(plaque), "regex")

    result = PseudonymizationStrategy().apply(content, [span])

    assert result == "La plaque est XX-001-XX."


#------------------------------------------------------------------------------------------------------
# PLUSIEURS EMAILS DIFFERENTS
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_plusieurs_emails():
    content = "Écrivez à a@gmail.com ou b@gmail.com."
    emails = ["a@gmail.com", "b@gmail.com"]

    spans = []
    for email in emails:
        start = content.index(email)
        spans.append(PIISpan(email, "EMAIL", start, start + len(email), "regex"))

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Écrivez à utilisateur1@example.com ou utilisateur2@example.com."


#------------------------------------------------------------------------------------------------------
# MEME EMAIL REPETE
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_email_repete():
    content = "Écrivez à test@gmail.com puis à test@gmail.com."
    email = "test@gmail.com"

    start1 = content.index(email)
    start2 = content.index(email, start1 + len(email))

    spans = [
        PIISpan(email, "EMAIL", start1, start1 + len(email), "regex"),
        PIISpan(email, "EMAIL", start2, start2 + len(email), "regex"),
    ]

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Écrivez à utilisateur1@example.com puis à utilisateur1@example.com."


#------------------------------------------------------------------------------------------------------
# PLUSIEURS TYPES DE PII
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_plusieurs_types():
    content = "Mail : a@gmail.com, téléphone : 06 12 34 56 78, plaque : AB-123-CD."

    pii = [
        ("a@gmail.com", "EMAIL"),
        ("06 12 34 56 78", "TELEPHONE"),
        ("AB-123-CD", "PLAQUE_ACTUELLE"),
    ]

    spans = []
    for valeur, type_pii in pii:
        start = content.index(valeur)
        spans.append(PIISpan(valeur, type_pii, start, start + len(valeur), "regex"))

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == (
        "Mail : utilisateur1@example.com, "
        "téléphone : 06 00 00 00 01, "
        "plaque : XX-001-XX."
    )


#------------------------------------------------------------------------------------------------------
# COMPTEUR COMMUN AUX PLAQUES
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_plusieurs_types_plaques():
    content = "Plaques : AB-123-CD, 1234 AB 35 et 123 CD 456."

    plaques = [
        ("AB-123-CD", "PLAQUE_ACTUELLE"),
        ("1234 AB 35", "PLAQUE_ANCIENNE"),
        ("123 CD 456", "PLAQUE_DIPLOMATIQUE"),
    ]

    spans = []
    for plaque, type_pii in plaques:
        start = content.index(plaque)
        spans.append(PIISpan(plaque, type_pii, start, start + len(plaque), "regex"))

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Plaques : XX-001-XX, XX-002-XX et XX-003-XX."


#------------------------------------------------------------------------------------------------------
# SPANS DANS LE DESORDRE
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_spans_desordonnes():
    content = "Premier : a@gmail.com, deuxième : b@gmail.com."
    email1 = "a@gmail.com"
    email2 = "b@gmail.com"

    start1 = content.index(email1)
    start2 = content.index(email2)

    span1 = PIISpan(email1, "EMAIL", start1, start1 + len(email1), "regex")
    span2 = PIISpan(email2, "EMAIL", start2, start2 + len(email2), "regex")

    result = PseudonymizationStrategy().apply(content, [span2, span1])

    assert result == "Premier : utilisateur1@example.com, deuxième : utilisateur2@example.com."


#------------------------------------------------------------------------------------------------------
# NORMALISATION EMAIL : MAJUSCULES
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_email_majuscules():
    content = "Contacts : Jean@Mail.fr et jean@mail.fr."
    emails = ["Jean@Mail.fr", "jean@mail.fr"]

    spans = []
    for email in emails:
        start = content.index(email)
        spans.append(PIISpan(email, "EMAIL", start, start + len(email), "regex"))

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Contacts : utilisateur1@example.com et utilisateur1@example.com."


#------------------------------------------------------------------------------------------------------
# NORMALISATION EMAIL : ESPACES
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_email_espaces():
    content = "Contact :  jean@mail.fr  ou jean@mail.fr."
    email_avec_espaces = " jean@mail.fr "
    email = "jean@mail.fr"

    start1 = content.index(email_avec_espaces)
    start2 = content.index(email, start1 + len(email_avec_espaces))

    spans = [
        PIISpan(
            email_avec_espaces,
            "EMAIL",
            start1,
            start1 + len(email_avec_espaces),
            "regex"
        ),
        PIISpan(email, "EMAIL", start2, start2 + len(email), "regex"),
    ]

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Contact : utilisateur1@example.com ou utilisateur1@example.com."


#------------------------------------------------------------------------------------------------------
# NORMALISATION TELEPHONE : SEPARATEURS
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_telephone_separateurs():
    content = "Numéros : 06 12 34 56 78 et 06.12.34.56.78."
    telephones = ["06 12 34 56 78", "06.12.34.56.78"]

    spans = []
    for telephone in telephones:
        start = content.index(telephone)
        spans.append(
            PIISpan(telephone, "TELEPHONE", start, start + len(telephone), "regex")
        )

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Numéros : 06 00 00 00 01 et 06 00 00 00 01."


#------------------------------------------------------------------------------------------------------
# NORMALISATION TELEPHONE : INDICATIF +33
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_telephone_international():
    content = "Numéros : +33 6 12 34 56 78 et 0612345678."
    telephones = ["+33 6 12 34 56 78", "0612345678"]

    spans = []
    for telephone in telephones:
        start = content.index(telephone)
        spans.append(
            PIISpan(telephone, "TELEPHONE", start, start + len(telephone), "regex")
        )

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Numéros : 06 00 00 00 01 et 06 00 00 00 01."


#------------------------------------------------------------------------------------------------------
# NORMALISATION TELEPHONE : INDICATIF 0033
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_telephone_0033():
    content = "Numéros : 0033612345678 et 0612345678."
    telephones = ["0033612345678", "0612345678"]

    spans = []
    for telephone in telephones:
        start = content.index(telephone)
        spans.append(
            PIISpan(telephone, "TELEPHONE", start, start + len(telephone), "regex")
        )

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Numéros : 06 00 00 00 01 et 06 00 00 00 01."


#------------------------------------------------------------------------------------------------------
# NORMALISATION PLAQUES : SEPARATEURS
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_plaque_separateurs():
    content = "Plaques : AB-123-CD, AB 123 CD et AB123CD."
    plaques = ["AB-123-CD", "AB 123 CD", "AB123CD"]

    spans = []
    for plaque in plaques:
        start = content.index(plaque)
        spans.append(
            PIISpan(plaque, "PLAQUE_ACTUELLE", start, start + len(plaque), "regex")
        )

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Plaques : XX-001-XX, XX-001-XX et XX-001-XX."


#------------------------------------------------------------------------------------------------------
# NORMALISATION PLAQUES : MAJUSCULES ET MINUSCULES
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_plaque_casse():
    content = "Plaques : ab-123-cd et AB-123-CD."
    plaques = ["ab-123-cd", "AB-123-CD"]

    spans = []
    for plaque in plaques:
        start = content.index(plaque)
        spans.append(
            PIISpan(plaque, "PLAQUE_ACTUELLE", start, start + len(plaque), "regex")
        )

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Plaques : XX-001-XX et XX-001-XX."


#------------------------------------------------------------------------------------------------------
# AUCUNE PII
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_aucune_pii():
    content = "Bonjour, ce document ne contient aucune PII."

    result = PseudonymizationStrategy().apply(content, [])

    assert result == content


#------------------------------------------------------------------------------------------------------
# CONSERVATION DU TEXTE ET DES POSITIONS
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_positions():
    content = "a@gmail.com et b@gmail.com sont deux adresses."
    emails = ["a@gmail.com", "b@gmail.com"]

    spans = []
    for email in emails:
        start = content.index(email)
        spans.append(PIISpan(email, "EMAIL", start, start + len(email), "regex"))

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == (
        "utilisateur1@example.com et utilisateur2@example.com sont deux adresses."
    )


#------------------------------------------------------------------------------------------------------
# TYPE DE PII INCONNU
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_type_inconnu():
    content = "Mon NIR est 189057512345678."
    nir = "189057512345678"
    start = content.index(nir)

    span = PIISpan(nir, "NIR", start, start + len(nir), "regex")

    with pytest.raises(ValueError):
        PseudonymizationStrategy().apply(content, [span])


#------------------------------------------------------------------------------------------------------
# DOCUMENT VIDE
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_document_vide():
    result = PseudonymizationStrategy().apply("", [])

    assert result == ""


#------------------------------------------------------------------------------------------------------
# REINITIALISATION DES COMPTEURS ENTRE DOCUMENTS
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_reinitialisation_compteurs():
    strategy = PseudonymizationStrategy()

    content1 = "Mail : premier@gmail.com."
    email1 = "premier@gmail.com"
    start1 = content1.index(email1)
    span1 = PIISpan(email1, "EMAIL", start1, start1 + len(email1), "regex")

    content2 = "Mail : second@gmail.com."
    email2 = "second@gmail.com"
    start2 = content2.index(email2)
    span2 = PIISpan(email2, "EMAIL", start2, start2 + len(email2), "regex")

    result1 = strategy.apply(content1, [span1])
    result2 = strategy.apply(content2, [span2])

    assert result1 == "Mail : utilisateur1@example.com."
    assert result2 == "Mail : utilisateur1@example.com."


#------------------------------------------------------------------------------------------------------
# PII DIFFERENTES APRES NORMALISATION
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_pii_distinctes():
    content = "Contacts : Jean@Mail.fr et marie@mail.fr."
    emails = ["Jean@Mail.fr", "marie@mail.fr"]

    spans = []
    for email in emails:
        start = content.index(email)
        spans.append(PIISpan(email, "EMAIL", start, start + len(email), "regex"))

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Contacts : utilisateur1@example.com et utilisateur2@example.com."


#------------------------------------------------------------------------------------------------------
# DEUX TELEPHONES DIFFERENTS
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_telephones_differents():
    content = "Numéros : 06 12 34 56 78 et 07 98 76 54 32."
    telephones = ["06 12 34 56 78", "07 98 76 54 32"]

    spans = []
    for telephone in telephones:
        start = content.index(telephone)
        spans.append(
            PIISpan(telephone, "TELEPHONE", start, start + len(telephone), "regex")
        )

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == "Numéros : 06 00 00 00 01 et 06 00 00 00 02."


#------------------------------------------------------------------------------------------------------
# REPETITION NORMALISEE ET COMPTEUR
#------------------------------------------------------------------------------------------------------

def test_pseudonymize_repetition_normalisee_compteur():
    content = "Contacts : Jean@Mail.fr, jean@mail.fr et marie@mail.fr."
    emails = ["Jean@Mail.fr", "jean@mail.fr", "marie@mail.fr"]

    spans = []
    for email in emails:
        start = content.index(email)
        spans.append(
            PIISpan(email, "EMAIL", start, start + len(email), "regex")
        )

    result = PseudonymizationStrategy().apply(content, spans)

    assert result == (
        "Contacts : utilisateur1@example.com, "
        "utilisateur1@example.com et utilisateur2@example.com."
    )
