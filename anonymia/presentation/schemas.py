from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from ..service.authentification_service import MOT_DE_PASSE_MAX_OCTETS


def _verifier_longueur_bcrypt(mot_de_passe: str) -> str:
    """bcrypt compte en octets : 40 lettres accentuées font déjà 80 octets."""
    if len(mot_de_passe.encode("utf-8")) > MOT_DE_PASSE_MAX_OCTETS:
        raise ValueError(f"Mot de passe trop long ({MOT_DE_PASSE_MAX_OCTETS} octets maximum)")
    return mot_de_passe


class LoginRequest(BaseModel):
    """Corps de la requête POST /auth/connexion."""

    login: str
    mot_de_passe: str

    # Même refus (422) pour tous les logins : la longueur ne révèle pas si un compte existe
    _longueur_mot_de_passe = field_validator("mot_de_passe")(_verifier_longueur_bcrypt)


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
    # Détecteurs qui ont répondu ; si le LLM n'y figure pas, l'analyse est en mode dégradé
    detecteurs: list[str] = []
    mode_degrade: bool = False
    # Catégories d'injection de prompt repérées (l'analyse n'est pas bloquée pour autant)
    types_injection: list[str] = []


class VerdictJugeResponse(BaseModel):
    """
    Verdict du juge d'injection LLM : jamais son explication, qui pourrait recopier du contenu.

    statut : detected (tentative de manipulation repérée), not_detected (rien repéré, ce qui ne
    prouve pas que le document est sûr) ou unavailable (le juge n'a pas pu répondre).
    """

    statut: Literal["detected", "not_detected", "unavailable"]
    type: str | None = Field(default=None, description="Type d'injection, seulement si statut = detected")


class CaviardageResponse(BaseModel):
    """Réponse de POST /documents/caviarder."""

    document_caviarde: str | None = None
    confirmation_requise: bool = False
    avertissements: list[str] = []
    detecteurs: list[str] = []
    mode_degrade: bool = False
    types_injection: list[str] = []
    # Verdict du juge LLM (FO3) ; None si aucun juge n'est actif ou si le document n'a pas été traité
    juge: VerdictJugeResponse | None = None


class StrategiesResponse(BaseModel):
    """Réponse de GET /documents/strategies."""

    strategies: list[str]


class TraitementResponse(BaseModel):
    """Métadonnées d'un traitement : jamais le contenu du document ni les PII."""

    id: int
    # None quand le compte auteur a été supprimé : la trace d'audit est conservée
    user_id: int | None = None
    date_traitement: datetime
    hash_document: str
    strategie_anonymisation: str
    detecteurs_contributeurs: str
    nb_pii_detectees: int
    types_pii: dict[str, int] = Field(default_factory=dict, description="Nombre de PII par type, ex. {'EMAIL': 2}")
    injection_suspectee: bool = False
    # Verdict du juge d'injection LLM ; None = pas de juge pour ce traitement
    juge_statut: str | None = None
    juge_type: str | None = None


class CreerUtilisateurRequest(BaseModel):
    """Corps de POST /admin/utilisateurs."""

    login: str = Field(min_length=1, max_length=255)
    mot_de_passe: str = Field(min_length=1, max_length=128)
    role: str

    _longueur_mot_de_passe = field_validator("mot_de_passe")(_verifier_longueur_bcrypt)


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