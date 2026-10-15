from pydantic import BaseModel


class LoginRequest(BaseModel):
    """Corps de la requête POST /login."""

    login: str
    mot_de_passe: str


class TokenResponse(BaseModel):
    """Réponse de POST /login : le jeton JWT à renvoyer ensuite à chaque requête."""

    access_token: str
    token_type: str = "bearer"
