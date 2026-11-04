"""
Décompte des types de PII d'un traitement, pour l'historique (F4).

On ne garde que le TYPE et le NOMBRE (« 2 EMAIL, 1 NOM ») : jamais le texte des données
détectées. Le décompte est stocké en base sous forme de texte, « EMAIL:2,NOM:1 ».
"""
from collections import Counter

from .business_objects.pii_span import PIISpan


def compter(spans: list[PIISpan]) -> dict[str, int]:
    """Nombre de PII par type, triés par nom de type."""
    return dict(sorted(Counter(s.type for s in spans).items()))


def vers_texte(decompte: dict[str, int]) -> str:
    """{'EMAIL': 2, 'NOM': 1} -> 'EMAIL:2,NOM:1' (chaîne vide s'il n'y a rien)."""
    return ",".join(f"{type_}:{nombre}" for type_, nombre in decompte.items())


def depuis_texte(texte: str | None) -> dict[str, int]:
    """
    'EMAIL:2,NOM:1' -> {'EMAIL': 2, 'NOM': 1}.

    Tolérant : les traitements anciens (sans types) donnent un dictionnaire vide, et un
    morceau mal formé est ignoré plutôt que de faire échouer la consultation.
    """
    decompte: dict[str, int] = {}
    for morceau in (texte or "").split(","):
        type_, separateur, nombre = morceau.partition(":")
        if separateur and type_.strip() and nombre.strip().isdigit():
            decompte[type_.strip()] = int(nombre)
    return decompte
