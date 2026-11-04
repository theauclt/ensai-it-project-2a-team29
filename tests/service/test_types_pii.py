from anonymia.service import types_pii
from anonymia.service.business_objects.pii_span import PIISpan


def span(type_, start=0):
    return PIISpan("x", type_, start, start + 1, "RegexDetector")


def test_compter_par_type_trie():
    spans = [span("NOM"), span("EMAIL", 5), span("EMAIL", 10)]

    assert types_pii.compter(spans) == {"EMAIL": 2, "NOM": 1}
    assert types_pii.compter([]) == {}


def test_aller_retour_texte():
    decompte = {"EMAIL": 2, "NOM": 1}

    assert types_pii.vers_texte(decompte) == "EMAIL:2,NOM:1"
    assert types_pii.depuis_texte("EMAIL:2,NOM:1") == decompte
    assert types_pii.vers_texte({}) == ""


def test_depuis_texte_tolere_les_anciens_traitements_et_les_morceaux_invalides():
    assert types_pii.depuis_texte("") == {}
    assert types_pii.depuis_texte(None) == {}
    assert types_pii.depuis_texte("EMAIL:2,n'importe quoi,NOM:x,:3,IBAN:1") == {"EMAIL": 2, "IBAN": 1}
