class PIISpan:
    """
    Représente une occurrence de PII détectée dans un document :
    le texte trouvé, son type, sa position, et le détecteur d'origine.
    """

    def __init__(
        self,
        text,
        type: str,
        start: int,
        end: int,
        source_detector: str
    ):
        """Constructor"""
        self.type = type
        self.text = text
        self.start = start
        self.end = end
        self.source_detector = source_detector