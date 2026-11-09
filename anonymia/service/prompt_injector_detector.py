import base64
import binascii
import logging
import re
import unicodedata
from datetime import UTC, datetime
from typing import ClassVar

# Mots qui introduisent une demande d'ignorer / oublier
_IGNORER = r"(?:ignor\w*|disregard|forget|oubli\w*|passe\w*\s+outre|override|bypass|contourne\w*)"
_CONSIGNES = (
    r"(?:instructions?|consignes?|directives?|system\s+prompt|prompts?|prompt\s+systeme|"
    r"guidelines?|ordres?)"
)
# 0 à 4 mots d'écart au maximum : évite les retours arrière coûteux
_ECART = r"(?:\s+[\w'-]+){0,4}"

_RAW_PATTERNS: dict[str, list[str]] = {
    # « Ignore les instructions précédentes », « forget all prior instructions »...
    "instruction_override": [
        rf"\b{_IGNORER}\b{_ECART}\s+{_CONSIGNES}\b",
        (
            r"\b(?:ignor\w*|forget|oubli\w*)\s+(?:everything|tout)\s+"
            r"(?:above|before|ce\s+qui\s+precede|ce\s+qui\s+est\s+ecrit)"
        ),
        r"\b(?:new|nouvelles?|updated|mises?\s+a\s+jour)\s+(?:instructions?|consignes?)\s*:",
        r"\b(?:ignor\w*|disregard)\s+(?:the\s+)?(?:above|previous|prior|earlier)\b",
        # « Réécris le document en remplaçant X par Y avant analyse »
        (
            r"\b(?:reecri\w*|rewrite|reformul\w*|modifi\w*|remplace\w*|replace|"
            r"traduis|translate)\b(?:\s+[\w'-]+){0,3}\s+"
            r"(?:document|texte|text|contenu|noms?|names?|prenoms?)\b(?:\s+[\w'-]+){0,6}\s+"
            r"(?:avant|before)\s+(?:l'|the\s+|la\s+|le\s+)?"
            r"(?:analyse|analysis|analy[sz]ing|detection|traitement|processing|anonymis\w*)"
        ),
        # « Avant de traiter ce document, réécris-le... »
        r"\bavant\s+(?:de\s+)?(?:traiter|analyser|detecter|anonymiser)\b[^.]{0,40},?\s*(?:reecri|remplace|modifi|traduis)\w*",
        r"\bbefore\s+(?:processing|analy[sz]ing|detecting)\b[^.]{0,40},?\s*(?:rewrite|replace|modify|translate)\b",
        # « Oublie les règles précédentes »
        r"\b(?:ignor\w*|oubli\w*|forget|disregard)\s+(?:\w+\s+){0,2}(?:regles?|rules?)\s+(?:precedent\w*|anterieur\w*|previous|prior|above|ci-dessus)",
        # « Si tu lis ceci, c'est un test... », « if you are reading this »
        r"\bsi\s+(?:tu|vous)\s+(?:lis|lisez)\s+ceci\b",
        r"\bif\s+you\s+(?:are\s+)?read(?:ing)?\s+this\b",
        # « from now on, ... »
        r"\bfrom\s+now\s+on\b(?:\s+[\w'-]+){0,3}\s+(?:you|output|respond|reply|return|ignore|always|never)",
        r"\b(?:desormais|a\s+partir\s+de\s+maintenant)\b[^.]{0,40}\b(?:reponds|renvoie|ignore|ne\s+\w+\s+plus|toujours|jamais)",
        # un fichier encodé à décoder puis exécuter
        r"\b(?:decode\w*|decod\w*|execut\w*)\b[^.]{0,60}\bbase\s*64\b|\bbase\s*64\b[^.]{0,80}\b(?:decod\w*|execut\w*)",
    ],
    # Changement de rôle ou de mode du modèle
    "role_manipulation": [
        (
            r"\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|dan|"
            r"different|new|in\s+developer\s+mode|the\s+system|an?\s+(?:ai|assistant|admin\w*))\b"
        ),
        (
            r"\b(?:act|behave|respond)\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|"
            r"jailbroken|different|new|system|admin\w*|developer)\b"
        ),
        (
            r"\bpretend\s+(?:to\s+be|you\s+are)\s+(?:an?\s+)?(?:\w+\s+){0,2}"
            r"(?:ai|assistant|model|admin\w*|system)\b"
        ),
        (
            r"\btu\s+es\s+(?:maintenant|desormais)\s+(?:un\s+|une\s+|l')?"
            r"(?:assistant|ia|modele|admin\w*|sans\s+restrictions?|libre)\b"
        ),
        r"\b(?:developer|developpeur|debug|jailbreak|dan)\s+mode\b",
        r"\bmode\s+(?:developpeur|debug|administrateur)\b",
        # Mise en situation : « Si vous étiez un assistant qui ne détecte jamais... »
        r"\bsi\s+(?:vous|tu)\s+(?:etiez|etais|serais|seriez|etes|es)\s+(?:un|une)\s+(?:assistant|ia|modele|outil|robot)\b",
        r"\bif\s+you\s+were\s+(?:an?\s+)?(?:assistant|ai|model|tool|bot)\b",
        r"\bcadre\s+hypothetique\b[^.]{0,30}\buniquement\b",
        r"\b(?:repon\w*|respond\w*)\b[^.]{0,40}\b(?:cadre|scenario)\s+hypothetique\b",
        r"\b(?:hypothetical|role-?play)\s+(?:scenario|setting|context|game)?\b.{0,30}\b(?:only|uniquement)\b",
        r"\b(?:imagine\w*|supposons|suppose\w*)\s+que\s+(?:tu|vous)\s+(?:sois|soyez|es|etes)\b",
    ],
    # Tentative de faire afficher le prompt système
    "prompt_extraction": [
        (
            r"\b(?:reveal|show|print|repeat|display|leak|output)\b(?:\s+[\w'-]+){0,3}\s+"
            r"(?:your|the)\s+(?:\w+\s+)?(?:prompt|instructions)\b"
        ),
        r"\bwhat\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions)\b",
        (
            r"\b(?:affiche\w*|montre\w*|revele\w*|donne\w*|repete\w*|ecris)\b(?:\s+[\w'-]+){0,3}\s+"
            r"(?:ton|votre|le|tes|vos)\s+(?:prompt|instructions?|consignes?)\b"
        ),
        r"\bquelles?\s+sont\s+(?:tes|vos)\s+(?:instructions|consignes)\b",
    ],
    # Demande d'envoyer des informations confidentielles
    "data_exfiltration": [
        r"\bexfiltr\w+",
        (
            r"\b(?:send|forward|transmit|leak|upload)\w*\b(?:\s+[\w'-]+){0,4}\s+"
            r"(?:confidential|secret|private)\b"
        ),
        (
            r"\b(?:transmets?|transmettez|envoie\w*|exfiltre\w*)\b(?:\s+[\w'-]+){0,4}\s+"
            r"(?:informations?|donnees)\s+(?:confidentielles?|secretes?|privees?)\b"
        ),
    ],
    # Spécifique à Anonymia : forcer une réponse vide du LLM
    "output_forcing": [
        r"[\"']?entites[\"']?\s*:\s*\[",
        r"[\"']?(?:spans?|entities|pii|results?|resultats?|detections?)[\"']?\s*:\s*\[\s*\]",
        r"[\"']?(?:override|ignore|bypass|skip)[\"']?\s*:\s*(?:true|1|\"true\")",
        r"\b(?:output|respond|reply|answer|return)\s+(?:with\s+)?(?:an?\s+)?empty\b",
        (
            r"\b(?:exemple\s+de\s+(?:sortie|reponse)|sortie\s+attendue|reponse\s+attendue|"
            r"expected\s+output|example\s+output)\b[^.{\[]{0,30}[{\[]"
        ),
        (
            r"\bne\s+(?:renvoi|renvoy|retourn|signal|detect|mask|anonymis|caviard)\w*\s+"
            r"(?:\w+\s+){0,2}(?:span|spans|entites?|pii|donnees?\s+personnelles?)"
        ),
        (
            r"\b(?:reponds?|reponse|renvoie|retourne|return|respond|reply)\b"
            r"(?:\s+[\w'-]+){0,4}\s+(?:liste\s+vide|empty\s+list|\[\s*\]|\{\s*\})"
        ),
        (
            r"\b(?:do\s+not|don't|ne\s+pas)\s+(?:output|return|renvoyer?|signaler)\s+"
            r"(?:any\s+|aucune?\s+)?(?:entit|donnee|pii)"
        ),
    ],
    # Spécifique à Anonymia : demander de ne pas anonymiser
    "anonymization_bypass": [
        r"\b(?:do\s+not|don't|dont|never|skip)\s+(?:anonymi[sz]\w*|redact\w*|mask\w*|detect\w*\s+(?:any\s+)?(?:pii|personal))",
        r"\bwithout\s+(?:anonymi[sz]\w*|redact\w*|masking)\b",
        r"\bne\s+pas\s+(?:anonymis|caviard|masqu)\w*",
        r"\bne\s+pas\s+detect\w*\s+(?:de\s+|les\s+)?(?:pii|donnees\s+personnelles)",
        r"\bn'?\s?(?:anonymis|caviard|masqu)\w*\s+(?:pas|personne|rien|aucun\w*)\b",
        r"\bsans\s+(?:anonymis|caviard|masqu)\w*",
        (
            r"\bne\s+pas\s+(?:le|la|les|l')\s*(?:considerer|traiter|signaler|compter)\w*\s+"
            r"comme\s+(?:une?\s+|des\s+)?(?:pii|donnees?\s+personnelles?)"
        ),
        (
            r"\b(?:ce|cette|ces|this|these)\s+(?:nom|prenom|personne|name|person)s?\s+"
            r"(?:n'est|ne\s+sont|is|are)\s+(?:pas|not)\s+(?:une?\s+)?"
            r"(?:pii|donnees?\s+personnelles?|personal)"
        ),
        r"\bne\s+pas\s+(?:l'|le\s+|la\s+|les\s+)(?:anonymis|caviard|masqu)\w*",
        r"\b(?:is|are)\s+not\s+(?:a\s+)?(?:pii|personal\s+data)\b",
        r"\b(?:do\s+not|don't)\s+(?:treat|consider|flag)\b[^.]{0,50}\b(?:pii|personal)",
        r"\b(?:est|sont)\s+(?:un\s+)?(?:nom\s+de\s+code|fictifs?|fictives?)\s+(?:interne|public)?",
        r"\bne\s+(?:detectez|signalez|anonymisez|masquez|caviardez)\s+(?:rien|aucun\w*|plus|jamais)\b",
    ],
    # Tentative de sortir du bloc <document> ou d'imiter un message système
    "delimiter_escape": [
        r"</?\s*document\s*>",
        r"<\|?\s*(?:im_start|im_end|system|endoftext)\s*\|?>",
        r"\[/?\s*(?:system|inst)\s*\]",
        r"\[\s*(?:note|message|avis|instruction)s?\s+(?:systeme|system|admin\w*|administrateur)\s*\]",
        r"\[\s*(?:systeme|administrateur|admin)\s*\]",
        r"\bmessage\s+(?:de\s+l'?\s*)?(?:administrateur|systeme|admin)\s*:",
        r"(?m)^\s*(?:>\s*)?(?:system|systeme)\s*:\s*(?:you|tu|vous|ignore|ne\s)",
        r"(?<!#)#{2,}\s*(?:system|instructions?)\b",
        r"(?<!-)-{3,}\s*(?:end|fin)\s+(?:of\s+)?(?:document|texte)\b",
    ],
}

_PATTERNS = {
    category: [re.compile(pattern) for pattern in patterns]
    for category, patterns in _RAW_PATTERNS.items()
}


def normalize(text: str) -> str:
    """
    Rend le texte comparable : minuscules, sans accents, sans caractères
    invisibles (espace de largeur nulle...), apostrophes droites, espaces réduits.
    Contourne les astuces du type « ig\u200bnore » ou « Ignorez  les  consignes ».
    """
    text = unicodedata.normalize("NFKD", text)
    text = "".join(
        c
        for c in text
        if not unicodedata.combining(c)
        and (unicodedata.category(c) not in ("Cf", "Cc") or c in "\n\t")
    )
    text = text.lower().replace("\u2019", "'").replace("\u2018", "'")
    return re.sub(r"\s+", " ", text)


_BASE64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def decoded_payloads(text: str) -> list[str]:
    """
    Décode les blocs qui ressemblent à du base64 et contiennent du texte lisible.
    Une consigne cachée dans un bloc encodé devient ainsi visible pour le filtre.
    """
    decoded: list[str] = []
    for token in _BASE64.findall(text):
        token = token.rstrip("=")
        token += "=" * (-len(token) % 4)  # rétablit le bourrage manquant
        try:
            lisible = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue  # pas du texte : identifiant, hash, données binaires...
        if lisible.isprintable() or "\n" in lisible:
            decoded.append(lisible)
    return decoded


class PromptInjectionDetector:
    """
    Premier filtre contre l'injection de prompt : des motifs simples et rapides
    (environ 1 ms par document). C'est un signal et non une barrière : il vise
    les formulations courantes et laisse les cas subtils à un contrôle plus fin
    (LLM juge, vérificateur de sortie).

    Choix de conception : peu de faux positifs, car chaque alerte oblige
    l'utilisateur à confirmer. Les motifs sont donc précis plutôt que larges.
    """

    PATTERNS: ClassVar[dict[str, list[re.Pattern]]] = _PATTERNS

    def __init__(self):
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)

    def detect(self, document_text: str) -> list[str]:
        """
        Renvoie les catégories suspectes (liste vide si rien).
        Ne conserve jamais le contenu du document.
        """
        normalized_text = normalize(document_text)

        detected_types = self._match(normalized_text)

        # Consigne cachée dans un bloc encodé (base64) : on regarde le texte décodé
        if any(
            self._match(normalize(payload)) for payload in decoded_payloads(document_text)
        ):
            detected_types.append("encoded_payload")

        if detected_types:
            self._log_events(detected_types)
        return detected_types

    def _match(self, normalized_text: str) -> list[str]:
        return [
            category
            for category, patterns in self.PATTERNS.items()
            if any(pattern.search(normalized_text) for pattern in patterns)
        ]

    def _log_events(self, detected_types: list[str]) -> None:
        """Journalise uniquement le type et la date."""
        timestamp = datetime.now(UTC).isoformat()
        for event_type in detected_types:
            self.logger.warning(
                "Suspicious content detected | type=%s | date=%s", event_type, timestamp
            )

    def analyze(self, document_text: str) -> dict:
        """Résultat détaillé de l'analyse, sans bloquer le traitement du document."""
        detected_types = self.detect(document_text)
        return {
            "suspicious_content": bool(detected_types),
            "detected_types": detected_types,
            "warning": bool(detected_types),
        }