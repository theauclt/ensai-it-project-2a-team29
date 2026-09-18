class PIISpan:
    """
    blabla description
    """

    def __init__(
        self,
        type: str,
        start: int,
        end: int,
        source_detector: str
    ):
        """Constructor"""
        self.type = type
        self.start = start
        self.end = end
        self.source_detector = source_detector