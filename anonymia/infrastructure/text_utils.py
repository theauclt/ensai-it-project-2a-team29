import unicodedata


def normalize_text(text: str) -> str:
    """
    Forme canonique pour comparer deux mentions : casse et accents ignorés.

    Ne sert qu'à construire une clé de cohérence, le texte du document
    n'est jamais modifié par cette fonction.
    """
    decomposed = unicodedata.normalize("NFD", text.casefold())
    return "".join(c for c in decomposed if not unicodedata.combining(c))