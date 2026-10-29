from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy
from .text_utils import normalize_key  # CHANGEMENT 1 : était normalize_text


class MaskingStrategy(AnonymisationStrategy):
    """
    Caviarde le document en remplaçant chaque PII détectée par un marqueur
    typé et numéroté, par exemple [NOM_1] ou [IBAN_1].

    Une même PII reçoit le même marqueur dans tout le document, quelle que
    soit sa casse ou ses accents ("DUPONT" et "Dupont" donnent tous deux [NOM_1]).
    """

    # Les trois formats de plaques partagent la même étiquette et le même compteur
    ETIQUETTES = {  # noqa: RUF012
        "TELEPHONE": "TEL",  # CHANGEMENT 2 : ligne ajoutée
        "PLAQUE_ACTUELLE": "PLAQUE",
        "PLAQUE_ANCIENNE": "PLAQUE",
        "PLAQUE_DIPLOMATIQUE": "PLAQUE",
    }

    def apply(self, content: str, spans: list[PIISpan]) -> str:
        # Mémorise les correspondances pour qu'une même PII garde le même marqueur
        replacements = {}

        # Un compteur par étiquette, repart de zéro à chaque document
        counters: dict[str, int] = {}

        replacements_to_apply = []

        # Numérotation dans l'ordre d'apparition (la première PII d'un type est la n°1)
        for span in sorted(spans, key=lambda span: span.start):
            etiquette = self.ETIQUETTES.get(span.type, span.type)
            # Clé de cohérence : deux écritures de la même valeur donnent la même clé
            key = (etiquette, normalize_key(span.type, span.text))

            if key not in replacements:
                counters[etiquette] = counters.get(etiquette, 0) + 1
                replacements[key] = f"[{etiquette}_{counters[etiquette]}]"

            replacements_to_apply.append((span, replacements[key]))

        # Remplacement de droite à gauche pour ne pas décaler les positions restantes
        for span, marker in reversed(replacements_to_apply):
            content = content[:span.start] + marker + content[span.end:]

        return content