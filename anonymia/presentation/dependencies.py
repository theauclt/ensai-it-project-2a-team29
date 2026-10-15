from ..persistence.postgres_user_repository import PostgresUserRepository
from ..service.authentification_service import AuthentificationService


def get_auth_service() -> AuthentificationService:
    """Construit le service d'authentification (injecté dans les routes via Depends)."""
    return AuthentificationService(PostgresUserRepository())
