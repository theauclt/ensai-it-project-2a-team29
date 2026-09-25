import re

from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.pii_detector import PIIDetector


class RegexDetector(PIIDetector):
    """
    Détecte les PII à format fixe (NIR, IBAN, email, téléphone ...)
    par expressions régulières.
    """

    PATTERNS = {  # noqa: RUF012
        "EMAIL": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
        "TELEPHONE":
        re.compile(r"(?<!\d)(?:(?:\+33|0033)\s?[1-9]|0[1-9])(?:[\s.\-]?\d{2}){4}(?!\d)"),
        "NIR": re.compile(r"^[12]\s?\d{2}\s?(0[1-9]|1[0-2])\s?\d{2}\s?\d{3}\s?\d{3}$"),
        # IBAN : candidats plausibles, double verif necessaire
        "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
        # format SIV actuel (depuis 2009) : AA-123-AA
        "PLAQUE_ACTUELLE": re.compile(r"\b[A-Z]{2}-\d{3}-[A-Z]{2}\b"),
        # ancien format FNI (avant 2009) : 1234 AB 75 (1 à 4 chiffres, 2-3 lettres, département)
        "PLAQUE_ANCIENNE": re.compile(r"\b\d{1,4}\s?[A-Z]{2,3}\s?\d{2,3}\b"),
    }

    # longueur exacte attendue par pays, pour la validation IBAN 
    IBAN_LENGTHS = {  # noqa: RUF012
        "DE": 22,
        "AD": 24,
        "SA": 24,
        "AT": 20,
        "BE": 16,
        "BR": 29,
        "BG": 22,
        "CY": 28,
        "HR": 21,
        "DK": 18,
        "AE": 23,
        "ES": 24,
        "EE": 20,
        "VA": 22,
        "FI": 18,
        "FR": 27,
        "GI": 23,
        "GR": 27,
        "HU": 28,
        "IE": 22,
        "IS": 26,
        "IL": 23,
        "IT": 27,
        "LV": 21,
        "LI": 21,
        "LT": 20,
        "LU": 20,
        "MT": 31,
        "MD": 24,
        "MC": 27,
        "NO": 15,
        "NL": 18,
        "PL": 28,
        "PT": 25,
        "RO": 24,
        "GB": 22,
        "SM": 27,
        "SK": 24,
        "SI": 19,
        "SE": 24,
        "CH": 21,
        "CZ": 24,
        "TR": 26,
    }

    async def detect(self, content: str) -> list[PIISpan]:
        spans: list[PIISpan] = []  # liste des résultats obtenus
        # on parcourt chaque type de PII connu
        for pii_type, pattern in self.PATTERNS.items():
            # finditer scanne tout le contenu d'un coup et renvoie
            # un match pour chaque occurrence trouvée, avec sa position.
            # finalement version sans split car pb de formats
            for match in pattern.finditer(content):
                # filtre spécifique à l'IBAN : rejette les candidats
                # dont la longueur ou la clé de contrôle est invalide
                if pii_type == "IBAN" and not self._is_valid_iban(match.group()):
                    continue

                if pii_type == "NIR" and not self._is_valid_nir(match.group()):
                    continue

                spans.append(PIISpan(
                    text=match.group(),
                    type=pii_type,
                    start=match.start(),
                    end=match.end(),
                    source_detector="RegexDetector",
                ))
        return spans

    def _is_valid_nir(self, nir: str) -> bool:
        """
        Vérifie qu'un candidat trouvé par le regex est un nir plausible :
        normalise le texte, vérifie sa longueur puis sa clé de contrôle.
        """
        nir = nir.replace(" ", "")

        if not nir.isdigit() or len(nir) != 15:
            return False

        num = int(nir[:13])
        cle = int(nir[13:])

        cle_calculee = 97 - (num % 97)

        return cle_calculee == cle

    def _is_valid_iban(self, candidate: str) -> bool:
        """
        Vérifie qu'un candidat trouvé par le regex est un IBAN plausible :
        normalise le texte, vérifie sa longueur selon le pays, puis sa clé de contrôle.
        """
        # normalisation : on met tout en majuscules et on retire les espaces,
        # pour gérer les IBAN écrits "FR76 3000 6000 ..." dans le document
        iban = candidate.upper().replace(" ", "")

        # les deux premiers caractères identifient le pays (ex. "FR")
        country = iban[:2]

        # chaque pays a une longueur d'IBAN fixe et connue 
        expected_length = self.IBAN_LENGTHS.get(country)

        # si le pays n'est pas dans notre table, ou si la longueur ne correspond pas,
        # ce n'est pas un IBAN valide pour ce pays : on rejette immédiatement
        if expected_length is None or len(iban) != expected_length:
            return False

        # la longueur est bonne : reste à vérifier la clé de contrôle mathématique
        return self._checksum_valid(iban)


def _checksum_valid(self, iban: str) -> bool:
    """
    Vérifie la clé de contrôle d'un IBAN selon la norme ISO 7064 (modulo 97).
    """
    # étape 1 de la norme : déplacer les 4 premiers caractères
    # (code pays + clé de contrôle) à la fin de la chaîne
    rearranged = iban[4:] + iban[:4]

    # étape 2 : remplacer chaque lettre par sa valeur numérique (A=10, B=11, ..., Z=35)
    # int(char, 36) interprète le caractère comme un chiffre en base 36 :
    # les chiffres 0-9 restent inchangés, les lettres A-Z deviennent 10-35
    # les chiffres restent des chiffres, donc on les laisse tels quels (str(...) sinon)
    converted = "".join(
        str(int(char, 36)) if char.isalpha() else char
        for char in rearranged
    )

    # étape 3 : le grand nombre obtenu doit être congruent à 1 modulo 97
    # sinon la clé de contrôle est invalide, l'IBAN n'existe pas
    return int(converted) % 97 == 1
