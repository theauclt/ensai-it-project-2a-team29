import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, status

from ..dependencies import build_auth_service
from ..service.authentification_service import AuthentificationService
from .schemas import LoginRequest, TokenResponse

router = APIRouter()

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60


def _creer_jeton(user_id: str, role: str) -> str:
    """Crée un jeton JWT signé avec la variable d'environnement JWT_SECRET."""
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRATION_MINUTES),
    }
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm=JWT_ALGORITHM)


@router.post("/login", response_model=TokenResponse)
async def login(
    data: LoginRequest,
    service: AuthentificationService = Depends(build_auth_service),
) -> TokenResponse:
    """Authentifie l'utilisateur et renvoie un jeton JWT."""
    user = await service.authentifier(data.login, data.mot_de_passe)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login ou mot de passe incorrect",
        )

    return TokenResponse(access_token=_creer_jeton(user.id, user.role))
