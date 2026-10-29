import re
import unicodedata


def normalize_text(text: str) -> str:
    """
    Forme canonique pour comparer deux mentions : casse et accents ignorés.

    Ne sert qu'à construire une clé de cohérence, le texte du document
    n'est jamais modifié par cette fonction.
    """
    decomposed = unicodedata.normalize("NFD", text.casefold())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def normalize_key(pii_type: str, text: str) -> str:
    """
    Clé de cohérence d'une PII : deux écritures de la même valeur donnent la même clé.

    - TELEPHONE : chiffres seuls, indicatif +33 / 0033 ramené à 0
    - PLAQUE_*  : séparateurs retirés, majuscules
    - EMAIL     : espaces autour retirés, casse ignorée
    - autres    : casse et accents ignorés
    """
    if pii_type == "TELEPHONE":
        digits = re.sub(r"\D", "", text)
        for prefix in ("0033", "33"):
            if digits.startswith(prefix):
                return "0" + digits[len(prefix):]
        return digits

    if pii_type.startswith("PLAQUE"):
        return re.sub(r"[\s-]", "", text).upper()

    if pii_type == "EMAIL":
        return text.strip().casefold()

    return normalize_text(text)