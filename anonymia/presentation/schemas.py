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
    confirmer: bool = False


class PIIResponse(BaseModel):
    """Une donnée personnelle détectée, avec sa position dans le document."""

    texte: str
    type: str
    debut: int
    fin: int
    detecteur: str
    confiance: float = Field(ge=0, le=1, description="Fiabilité de la détection, de 0 à 1")


class AnalyseResponse(BaseModel):
    """Réponse de POST /documents/analyser."""

    pii: list[PIIResponse]


class CaviardageResponse(BaseModel):
    """Réponse de POST /documents/caviarder."""

    document_caviarde: str | None = None
    confirmation_requise: bool = False
    avertissements: list[str] = []


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
    types_pii: dict[str, int] = Field(default_factory=dict, description="Nombre de PII par type, ex. {'EMAIL': 2}")
    injection_suspectee: bool = False


class CreerUtilisateurRequest(BaseModel):
    """Corps de POST /admin/utilisateurs."""

    login: str = Field(min_length=1, max_length=255)
    mot_de_passe: str = Field(min_length=1, max_length=128)
    role: str


class ChangerRoleRequest(BaseModel):
    """Corps de PATCH /admin/utilisateurs/{id}/role."""

    role: str


class ActivationRequest(BaseModel):
    """Corps de PATCH /admin/utilisateurs/{id}/activation."""

    est_active: bool


class UtilisateurResponse(BaseModel):
    """Un compte : jamais le hash du mot de passe."""

    id: int
    login: str
    role: str
    est_active: bool
    date_creation: datetime | None = None
