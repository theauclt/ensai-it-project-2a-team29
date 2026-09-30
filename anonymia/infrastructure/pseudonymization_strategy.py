from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy


class PseudonymizationStrategy(AnonymisationStrategy):
    """
    Caviarde le document selon une strategie de pseudonymisation des PII détéctées. 

    Une même PII est remplacé par le même pseudonyme dans tout le document.
    """

    def apply(self, content: str, spans: list[PIISpan]) -> str:
    replacements = {}

    for span in sorted(spans, key=lambda span: span.start, reverse=True):
        key = (span.type, span.text)

        if key not in replacements:
            replacements[key] = self._generate_pseudonym(span)

        pseudonym = replacements[key]

        content = (
            content[:span.start]
            + pseudonym
            + content[span.end:]
        )

    return content



    def _generate_pseudonym(self, span: PIISpan) -> str:

        """
        Génère un pseudonyme adapté au type de PII détectée.
        """

        if span.type == "EMAIL":
            return self._pseudonymize_email(span)

        if span.type == "TELEPHONE":
            return self._pseudonymize_phone(span)

        if span.type == "NIR":
            return self._pseudonymize_nir(span)

        if span.type == "IBAN":
            return self._pseudonymize_iban(span)

        raise ValueError(
            f"Type de PII non pris en charge : {span.type}"
        )

    
    

