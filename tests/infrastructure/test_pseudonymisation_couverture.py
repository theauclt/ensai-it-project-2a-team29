import pytest

from anonymia.infrastructure.pseudonymization_strategy import PseudonymizationStrategy
from anonymia.service.business_objects.pii_span import PIISpan


def span(texte, type_, contenu, debut=None):
    start = contenu.index(texte) if debut is None else debut
    return PIISpan(texte, type_, start, start + len(texte), "test")


@pytest.mark.parametrize(
    ("texte", "type_", "attendu"),
    [
        ("jean@mail.fr", "EMAIL", "utilisateur1@example.com"),
        ("06 12 34 56 78", "TELEPHONE", "06 00 00 00 01"),
        ("1 95 05 78 006 048 25", "NIR", "1 00 01 01 001 001"),
        ("FR7630006000011234567890189", "IBAN", "FR00" + "0" * 20 + "001"),
        ("AB-123-CD", "PLAQUE_ACTUELLE", "XX-001-XX"),
        ("Claire", "PRENOM", "Camille"),
        ("Martin", "NOM", "Martin"),
        ("Nantes", "LIEU", "Commune 1"),
        ("Mairie", "ORGANISATION", "Organisation 1"),
        ("12 rue des Lilas", "ADRESSE", "1 rue de l'Exemple"),
        ("12 mars 1985", "DATE_NAISSANCE", "01/01/1950"),
        ("chef de service", "POSTE", "Agent 1"),
    ],
)
def test_chaque_type_recoit_son_pseudonyme(texte, type_, attendu):
    contenu = f"Début {texte} fin"

    resultat = PseudonymizationStrategy().apply(contenu, [span(texte, type_, contenu)])

    assert resultat == f"Début {attendu} fin"


def test_les_noms_en_majuscules_restent_en_majuscules():
    contenu = "DUPONT et Dupont"
    spans = [span("DUPONT", "NOM", contenu, 0), span("Dupont", "NOM", contenu, 10)]

    resultat = PseudonymizationStrategy().apply(contenu, spans)

    assert resultat == "MARTIN et Martin"  # même personne, casse d'origine respectée


def test_apres_un_tour_complet_un_suffixe_evite_les_doublons():
    strategie = PseudonymizationStrategy()
    noms = [f"Nom{chr(97 + i)}" for i in range(12)]  # 12 personnes différentes, 10 noms en liste
    contenu = "|".join(noms)
    spans = [span(n, "NOM", contenu) for n in noms]

    resultat = strategie.apply(contenu, spans).split("|")

    assert len(set(resultat)) == 12  # aucun pseudonyme partagé
    assert resultat[10] == "Martin 2"


def test_prenoms_apres_un_tour_complet():
    prenoms = [f"Pre{chr(97 + i)}" for i in range(11)]
    contenu = "|".join(prenoms)

    resultat = PseudonymizationStrategy().apply(
        contenu, [span(p, "PRENOM", contenu) for p in prenoms]
    ).split("|")

    assert resultat[10] == "Camille 2"


def test_les_dates_distinctes_ont_des_annees_distinctes():
    contenu = "12 mars 1985 et 4 mai 1990"
    spans = [span("12 mars 1985", "DATE_NAISSANCE", contenu), span("4 mai 1990", "DATE_NAISSANCE", contenu)]

    assert PseudonymizationStrategy().apply(contenu, spans) == "01/01/1950 et 01/01/1951"