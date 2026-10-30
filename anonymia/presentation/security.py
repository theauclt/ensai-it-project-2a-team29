import os
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..service.business_objects.user import User

ALGORITHM = "HS256"
DUREE_JETON = timedelta(minutes=30)

# auto_error=False : c'est nous qui renvoyons un 401 propre (et non un 403 par défaut)
_bearer = HTTPBearer(auto_error=False)


def _secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise RuntimeError("Variable d'environnement manquante : JWT_SECRET")
    return secret


def create_token(user: User) -> str:
    """Crée un jeton signé qui identifie l'utilisateur pendant 30 minutes."""
    payload = {
        "sub": str(user.id),
        "login": user.login,
        "role": user.role,
        "exp": datetime.now(UTC) + DUREE_JETON,
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> User:
    """Dépendance FastAPI : l'utilisateur identifié par le jeton, ou une erreur 401."""
    non_authentifie = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentification requise",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise non_authentifie

    try:
        payload = jwt.decode(credentials.credentials, _secret(), algorithms=[ALGORITHM])
        return User(
            id=int(payload["sub"]),
            login=payload["login"],
            password_hash="",
            role=payload["role"],
        )
    except (jwt.PyJWTError, KeyError, ValueError):
        # jeton expiré, falsifié ou mal formé : même réponse dans tous les cas
        raise non_authentifie from None