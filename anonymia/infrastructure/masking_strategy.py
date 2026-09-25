from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy


class MaskingStrategy(AnonymisationStrategy):
    """
    Caviarde le document selon une strategie de masquage des PII détéctées
    """
    Mask = {  # noqa: RUF012
        "EMAIL": "EMAIL_",
        "TELEPHONE": "TEL_",
        "NIR": "NIR_",
        "IBAN": "IBAN_",
    }

    def apply(self, content: str, spans: list[PIISpan]) -> str:
        mask_count = {
            "EMAIL": 1,
            "TELEPHONE": 1,
            "NIR": 1,
            "IBAN": 1,
        }
        for span in reversed(spans):
            mask = "[" + self.Mask[span.type] + str(mask_count[span.type]) + "]"
            mask_count[span.type] += 1
            content = content[:span.start] + mask + content[span.end:]
            return content




