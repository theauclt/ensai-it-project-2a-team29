from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy


class PseudonymizationStrategy(AnonymisationStrategy):
    """
    Caviarde le document selon une stratégie de pseudonymisation des PII détectées.

    Une même PII est remplacée par le même pseudonyme dans tout le document.
    """

    def apply(self, content: str, spans: list[PIISpan]) -> str:
        # Mémorise les correspondances pour qu'une même PII garde le même pseudonyme dans tout le document
        replacements = {}

        # Compteurs pour indexer les PII d'un même type
        counters = {
            "EMAIL": 0,
            "TELEPHONE": 0,
            "PLAQUE": 0,
        }

        replacements_to_apply = []

        # Attribution des pseudonymes dans l'ordre d'apparition des PII (le premier a le numero 1)
        for span in sorted(spans, key=lambda span: span.start):
            key = (span.type, span.text)

            if key not in replacements:
                replacements[key] = self._generate_pseudonym(
                    span,
                    counters,
                )

            replacements_to_apply.append(
                (span, replacements[key])
            )

        # Remplacement de droite à gauche pour ne pas décaler les positions des PII restantes
        for span, pseudonym in reversed(replacements_to_apply):
            content = (
                content[:span.start]
                + pseudonym
                + content[span.end:]
            )

        return content

    def _generate_pseudonym(
        self,
        span: PIISpan,
        counters: dict[str, int],
    ) -> str:
        """Choisit la méthode de pseudonymisation selon le type de PII."""

        if span.type == "EMAIL":
            counters["EMAIL"] += 1
            return self._pseudonymize_email(counters["EMAIL"])

        if span.type == "TELEPHONE":
            counters["TELEPHONE"] += 1
            return self._pseudonymize_phone(counters["TELEPHONE"])

        # Tous les formats de plaques sont remplacés par un format SIV
        if span.type in {
            "PLAQUE_ACTUELLE",
            "PLAQUE_ANCIENNE",
            "PLAQUE_DIPLOMATIQUE",
        }:
            counters["PLAQUE"] += 1
            return self._pseudonymize_plate(counters["PLAQUE"])

        # Évite de laisser passer une PII détectée mais non prise en charge
        raise ValueError(
            f"Type de PII non pris en charge : {span.type}"
        )

    def _pseudonymize_email(self, index: int) -> str:
        """Génère une adresse e-mail générique."""
        return f"utilisateur{index}@example.com"

    def _pseudonymize_phone(self, index: int) -> str:
        """Génère un numéro de téléphone fictif français."""
        return f"06 00 00 00 {index:02d}"

    def _pseudonymize_plate(self, index: int) -> str:
        """Génère une plaque fictive au format SIV."""
        return f"XX-{index:03d}-XX"
    

