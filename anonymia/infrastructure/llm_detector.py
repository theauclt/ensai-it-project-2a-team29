from ..service.business_objects.pii_span import PIISpan
from ..service.interfaces.pii_detector import PIIDetector


class LLMDetector(PIIDetector):
    """
    Détecte les PII dépendantes du contexte
    (Nom, date de naissance, etc) par LLM.
    """
    
    async def detect(self, content: str) -> list[PIISpan]:
        #blabla
