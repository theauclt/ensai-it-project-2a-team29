import re

from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy

# TODO : adapter pour pii detectées par LLM

PLATE_TYPES = {"PLAQUE_ACTUELLE", "PLAQUE_ANCIENNE", "PLAQUE_DIPLOMATIQUE"}


class PseudonymizationStrategy(AnonymisationStrategy):

    def apply(self, content: str, spans: list[PIISpan]) -> str:
        replacements = {}
        counters = {"EMAIL": 0, "TELEPHONE": 0, "PLAQUE": 0}
        replacements_to_apply = []

        for span in sorted(spans, key=lambda span: span.start):
            key = self._build_key(span)

            if key not in replacements:
                replacements[key] = self._generate_pseudonym(span, counters)

            replacements_to_apply.append((span, replacements[key]))

        for span, pseudonym in reversed(replacements_to_apply):
            content = content[:span.start] + pseudonym + content[span.end:]

        return content

    def _build_key(self, span: PIISpan) -> tuple[str, str]:
        """
        Clé d'identité d'une PII : deux écritures différentes de la même
        donnée donnent la même clé.
        """
        if span.type == "EMAIL":
            return ("EMAIL", self._normalize_email(span.text))

        if span.type == "TELEPHONE":
            return ("TELEPHONE", self._normalize_phone(span.text))

        if span.type in PLATE_TYPES:
            # Famille "PLAQUE" : le type de format ne fait pas partie de l'identité
            return ("PLAQUE", self._normalize_plate(span.text))

        raise ValueError(f"Type de PII non pris en charge : {span.type}")

    def _normalize_email(self, text: str) -> str:
        """Jean@Mail.fr -> jean@mail.fr"""
        return text.strip().lower()

    def _normalize_phone(self, text: str) -> str:
        """
        '06 12 34 56 78', '06.12.34.56.78', '+33 6 12 34 56 78'
        et '0033612345678' -> '0612345678'
        """
        digits = re.sub(r"\D", "", text)

        if digits.startswith("0033"):
            digits = "0" + digits[4:]
        elif digits.startswith("33") and len(digits) == 11:
            digits = "0" + digits[2:]

        return digits

    def _normalize_plate(self, text: str) -> str:
        """'ab-123-cd', 'AB 123 CD' et 'AB123CD' -> 'AB123CD'"""
        return re.sub(r"[\s\-]", "", text).upper()

    # _generate_pseudonym et les _pseudonymize_* restent inchangés

    def _generate_pseudonym(self, span, counters):
        if span.type == "EMAIL":
            counters["EMAIL"] += 1
            return self._pseudonymize_email(counters["EMAIL"])

        if span.type == "TELEPHONE":
            counters["TELEPHONE"] += 1
            return self._pseudonymize_phone(counters["TELEPHONE"])

        if span.type in PLATE_TYPES:
            counters["PLAQUE"] += 1
            return self._pseudonymize_plate(counters["PLAQUE"])

        raise ValueError(f"Type de PII non pris en charge : {span.type}")

    def _pseudonymize_email(self, index):
        return f"utilisateur{index}@example.com"

    def _pseudonymize_phone(self, index):
        return f"06 00 00 00 {index:02d}"

    def _pseudonymize_plate(self, index):
        return f"XX-{index:03d}-XX"