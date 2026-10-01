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
            "EMAIL": 1,
            "TELEPHONE": 1,
            "NIR": 1,
            "IBAN": 1,
            "PLAQUE": 1,
        }

        # Remplacement de droite à gauche pour conserver les positions
        for span in reversed(spans):

            # toutes les plaques partagent le même compteur
            if span.type in {
                "PLAQUE_ACTUELLE",
                "PLAQUE_ANCIENNE",
                "PLAQUE_DIPLOMATIQUE",
            }:
                count_type = "PLAQUE"
            else:
                count_type = span.type

            mask = (
                "["
                + self.Mask[span.type]
                + str(mask_count[count_type])
                + "]"
            )

            mask_count[count_type] += 1

            content = (
                content[:span.start]
                + mask
                + content[span.end:]
            )

        return content