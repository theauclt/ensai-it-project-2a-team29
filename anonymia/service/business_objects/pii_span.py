class PIISpan:
    """
    Représente une occurrence de PII détectée dans un document :
    le texte trouvé, son type, sa position, le détecteur d'origine
    et un niveau de confiance entre 0 et 1.

    La confiance vaut 1.0 par défaut : c'est celle des expressions régulières, dont les
    formats sont sûrs. Seul le LLM fournit une confiance variable. Elle sert uniquement à
    informer l'utilisateur : elle ne décide jamais de ce qui est caviardé.
    """

    def __init__(
        self,
        text,
        type: str,
        start: int,
        end: int,
        source_detector: str,
        confidence: float = 1.0,
    ):
        """Constructor"""
        self.type = type
        self.text = text
        self.start = start
        self.end = end
        self.source_detector = source_detector
        self.confidence = confidence
