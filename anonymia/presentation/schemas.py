from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Corps de la requête POST /auth/connexion."""

    login: str
    mot_de_passe: str


class TokenResponse(BaseModel):
    """Réponse de POST /auth/connexion : le jeton JWT à renvoyer ensuite à chaque requête."""

    access_token: str
    token_type: str = "bearer"


class DocumentRequest(BaseModel):
    """Corps de POST /documents/analyser : le texte à analyser."""

    contenu: str = Field(min_length=1, max_length=100_000)


class CaviarderRequest(DocumentRequest):
    """Corps de POST /documents/caviarder : le texte et la stratégie choisie."""

    strategie: str = "masking"


class PIIResponse(BaseModel):
    """Une donnée personnelle détectée, avec sa position dans le document."""

    texte: str
    type: str
    debut: int
    fin: int
    detecteur: str


class AnalyseResponse(BaseModel):
    """Réponse de POST /documents/analyser."""

    pii: list[PIIResponse]


class CaviardageResponse(BaseModel):
    """Réponse de POST /documents/caviarder."""

    document_caviarde: str


class StrategiesResponse(BaseModel):
    """Réponse de GET /documents/strategies."""

    strategies: list[str]


class TraitementResponse(BaseModel):
    """Métadonnées d'un traitement : jamais le contenu du document ni les PII."""

    id: int
    user_id: int
    date_traitement: datetime
    hash_document: str
    strategie_anonymisation: str
    detecteurs_contributeurs: str
    nb_pii_detectees: int