from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy
from .text_utils import normalize_text


class PseudonymizationStrategy(AnonymisationStrategy):
    """
    Caviarde le document selon une stratégie de pseudonymisation des PII détectées.

    Une même PII est remplacée par le même pseudonyme dans tout le document,
    quelle que soit sa casse ou ses accents ("DUPONT", "Dupont" et "dupont"
    désignent la même personne).
    """

    PRENOMS = [  # noqa: RUF012
        "Camille", "Alex", "Dominique", "Claude", "Sacha",
        "Morgan", "Charlie", "Robin", "Andrea", "Yannick",
    ]
    NOMS = [  # noqa: RUF012
        "Martin", "Bernard", "Durand", "Dubois", "Moreau",
        "Laurent", "Simon", "Michel", "Lefebvre", "Leroy",
    ]

    # Type de PII -> groupe de numérotation (les 3 formats de plaques partagent un compteur)
    GROUPES = {  # noqa: RUF012
        "EMAIL": "EMAIL",
        "TELEPHONE": "TELEPHONE",
        "NIR": "NIR",
        "IBAN": "IBAN",
        "PLAQUE_ACTUELLE": "PLAQUE",
        "PLAQUE_ANCIENNE": "PLAQUE",
        "PLAQUE_DIPLOMATIQUE": "PLAQUE",
        "PRENOM": "PRENOM",
        "NOM": "NOM",
        "LIEU": "LIEU",
        "ORGANISATION": "ORGANISATION",
        "ADRESSE": "ADRESSE",
        "DATE_NAISSANCE": "DATE_NAISSANCE",
        "POSTE": "POSTE",
    }

    def apply(self, content: str, spans: list[PIISpan]) -> str:
        # Mémorise les correspondances pour qu'une même PII garde le même pseudonyme
        replacements = {}

        # Un compteur par groupe, repart de zéro à chaque document
        counters: dict[str, int] = {}

        replacements_to_apply = []

        # Attribution des pseudonymes dans l'ordre d'apparition (le premier a le numéro 1)
        for span in sorted(spans, key=lambda span: span.start):
            # Clé normalisée : "Dupont", "DUPONT" et "dupont" donnent la même clé
            key = (span.type, normalize_text(span.text))

            if key not in replacements:
                replacements[key] = self._generate_pseudonym(span, counters)

            replacements_to_apply.append((span, replacements[key]))

        # Remplacement de droite à gauche pour ne pas décaler les positions restantes
        for span, pseudonym in reversed(replacements_to_apply):
            # Respect de la casse d'origine pour les noms écrits en majuscules
            if span.type in {"NOM", "PRENOM"} and span.text.isupper():
                pseudonym = pseudonym.upper()

            content = content[:span.start] + pseudonym + content[span.end:]

        return content

    def _generate_pseudonym(self, span: PIISpan, counters: dict[str, int]) -> str:
        """Choisit la méthode de pseudonymisation selon le type de PII."""
        groupe = self.GROUPES.get(span.type)

        # Évite de laisser passer une PII détectée mais non prise en charge
        if groupe is None:
            raise ValueError(f"Type de PII non pris en charge : {span.type}")

        # Incrémente le compteur du groupe : c'est le numéro du pseudonyme
        counters[groupe] = counters.get(groupe, 0) + 1
        index = counters[groupe]

        generateurs = {
            "EMAIL": self._pseudonymize_email,
            "TELEPHONE": self._pseudonymize_phone,
            "NIR": self._pseudonymize_nir,
            "IBAN": self._pseudonymize_iban,
            "PLAQUE": self._pseudonymize_plate,
            "PRENOM": self._pseudonymize_prenom,
            "NOM": self._pseudonymize_nom,
            "LIEU": self._pseudonymize_lieu,
            "ORGANISATION": self._pseudonymize_organisation,
            "ADRESSE": self._pseudonymize_adresse,
            "DATE_NAISSANCE": self._pseudonymize_date,
            "POSTE": self._pseudonymize_poste,
        }
        return generateurs[groupe](index)

    # ------------------------------------------------------------------
    # Formats fixes (regex)
    # ------------------------------------------------------------------

    def _pseudonymize_email(self, index: int) -> str:
        """Génère une adresse e-mail générique."""
        return f"utilisateur{index}@example.com"

    def _pseudonymize_phone(self, index: int) -> str:
        """Génère un numéro de téléphone fictif français."""
        return f"06 00 00 00 {index:02d}"

    def _pseudonymize_nir(self, index: int) -> str:
        """Génère un NIR fictif (13 chiffres) : seul le numéro d'ordre varie."""
        return f"1 00 01 01 001 {index:03d}"

    def _pseudonymize_iban(self, index: int) -> str:
        """Génère un IBAN fictif de 27 caractères (clé 00, donc jamais un vrai IBAN)."""
        return f"FR00{'0' * 20}{index:03d}"

    def _pseudonymize_plate(self, index: int) -> str:
        """Génère une plaque fictive au format SIV."""
        return f"XX-{index:03d}-XX"

    # ------------------------------------------------------------------
    # Formats libres (LLM)
    # ------------------------------------------------------------------

    def _pseudonymize_prenom(self, index: int) -> str:
        """Prénom mixte de la liste ; un suffixe évite les doublons après un tour complet."""
        i = index - 1
        tour = i // len(self.PRENOMS)
        return self.PRENOMS[i % len(self.PRENOMS)] + (f" {tour + 1}" if tour else "")

    def _pseudonymize_nom(self, index: int) -> str:
        """Nom générique de la liste, même principe que pour les prénoms."""
        i = index - 1
        tour = i // len(self.NOMS)
        return self.NOMS[i % len(self.NOMS)] + (f" {tour + 1}" if tour else "")

    def _pseudonymize_lieu(self, index: int) -> str:
        """Génère un nom de lieu générique."""
        return f"Commune {index}"

    def _pseudonymize_organisation(self, index: int) -> str:
        """Génère un nom d'organisation générique."""
        return f"Organisation {index}"

    def _pseudonymize_adresse(self, index: int) -> str:
        """Génère une adresse postale fictive."""
        return f"{index} rue de l'Exemple"

    def _pseudonymize_date(self, index: int) -> str:
        """Génère une date de naissance fictive ; l'année varie pour distinguer deux dates."""
        return f"01/01/{1950 + (index - 1) % 50}"

    def _pseudonymize_poste(self, index: int) -> str:
        """Génère un intitulé de poste générique."""
        return f"Agent {index}"