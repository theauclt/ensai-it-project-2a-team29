from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy

class MaskingStrategy(AnonymisationStrategy):
    """
    Caviarde le document selon une stratégie de masquage des PII détectées.
    """

    # Associe chaque type de PII au masque correspondant
    Mask = {  # noqa: RUF012
        "EMAIL": "EMAIL_",
        "TELEPHONE": "TEL_",
        "NIR": "NIR_",
        "IBAN": "IBAN_",
        "PLAQUE_ACTUELLE": "PLAQUE_",
        "PLAQUE_ANCIENNE": "PLAQUE_",
        "PLAQUE_DIPLOMATIQUE": "PLAQUE_",
    }

    def apply(self, content: str, spans: list[PIISpan]) -> str:
        # Compteurs pour numéroter les PII de chaque type
        mask_count = {
            "EMAIL_": 1,
            "TEL_": 1,
            "NIR_": 1,
            "IBAN_": 1,
            "PLAQUE_": 1,
        }
        replacements = {}
        replacements_to_apply = []

        #Application des masques dans l'ordre d'apparition
        for span in sorted(spans, key=lambda span: span.start):

            key = (span.type, span.text)

            if key not in replacements:

                mask_type = self.Mask[span.type]

                replacements[key] = f"[{mask_type}{mask_count[mask_type]}]"
                
                mask_count[mask_type] += 1

            replacements_to_apply.append((span, replacements[key]))

        # Remplacement de droite à gauche pour conserver les positions

        for span, mask in reversed(replacements_to_apply):

            content = content[:span.start] + mask + content[span.end:]

        return content