from fastapi import APIRouter, Depends, HTTPException, status

from ..service.authentification_service import AuthentificationService
from .providers import get_auth_service
from .schemas import LoginRequest, TokenResponse
from .security import create_token

router = APIRouter(prefix="/auth", tags=["Authentification"])


@router.post("/connexion", response_model=TokenResponse)
async def connexion(
    body: LoginRequest,
    auth: AuthentificationService = Depends(get_auth_service),
) -> TokenResponse:
    """Se connecter : renvoie le jeton à fournir dans les requêtes suivantes."""
    user = await auth.authentifier(body.login, body.mot_de_passe)
    if user is None:
        # même message pour login inconnu, compte désactivé et mauvais mot de passe
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides")
    return TokenResponse(access_token=create_token(user))