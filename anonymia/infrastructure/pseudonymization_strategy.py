from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy


class PseudonymizationStrategy(AnonymisationStrategy):
    """
    Caviarde le document selon une stratégie de pseudonymisation
    des PII détectées.

    Une même PII est remplacée par le même pseudonyme
    dans tout le document.
    """

    def apply(self, content: str, spans: list[PIISpan]) -> str:
        # Mémorise les correspondances entre PII et pseudonymes
        replacements = {}

        # Compteurs propres à chaque type de pseudonyme
        counters = {
            "EMAIL": 0,
            "TELEPHONE": 0,
            "PLAQUE": 0,
        }

        # On parcourt PII de droite à gauche afin que les remplacements ne décalent pas les positions suivantes

            # Si cette PII n'a pas encore été pseudonymisée
            if key not in replacements:
                replacements[key] = self._generate_pseudonym(
                    span,
                    counters,
                )

            pseudonym = replacements[key]

            # Remplacement de la PII dans le document
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
        """
        Génère un pseudonyme adapté au type de PII détectée.
        """

        if span.type == "EMAIL":
            counters["EMAIL"] += 1
            return self._pseudonymize_email(counters["EMAIL"])

        if span.type == "TELEPHONE":
            counters["TELEPHONE"] += 1
            return self._pseudonymize_phone(counters["TELEPHONE"])

        if span.type in {
            "PLAQUE_ACTUELLE",
            "PLAQUE_ANCIENNE",
            "PLAQUE_DIPLOMATIQUE",
        }:
            counters["PLAQUE"] += 1
            return self._pseudonymize_plate(counters["PLAQUE"])

        # ajouter NIR et IBAN / règles ?

        raise ValueError(
            f"Type de PII non pris en charge : {span.type}"
        )

    def _pseudonymize_email(self, index: int) -> str:
        """
        Génère une adresse e-mail générique.
        """
        return f"utilisateur{index}@example.com"

    def _pseudonymize_phone(self, index: int) -> str:
        """
        Génère un numéro de téléphone fictif au format français.
        """
        return f"06 00 00 00 {index:02d}"

    def _pseudonymize_plate(self, index: int) -> str:
        """
        Génère une plaque fictive au format SIV français.
        """
        return f"XX-{index:03d}-XX"
    
    

