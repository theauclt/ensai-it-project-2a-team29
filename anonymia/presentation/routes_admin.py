from fastapi import APIRouter, Depends, HTTPException, status

from ..service.admin_service import (
    AdminService,
    CompteIntrouvableError,
    DonneeInvalideError,
    LoginDejaPrisError,
    OperationInterditeError,
)
from ..service.business_objects.user import User
from .providers import get_admin_service
from .schemas import (
    ActivationRequest,
    ChangerRoleRequest,
    CreerUtilisateurRequest,
    UtilisateurResponse,
)
from .security import get_current_user

router = APIRouter(prefix="/admin/utilisateurs", tags=["Administration"])


def _erreur_http(exc: Exception) -> HTTPException:
    """Traduit une erreur métier en code HTTP."""
    if isinstance(exc, PermissionError):
        code = status.HTTP_403_FORBIDDEN
    elif isinstance(exc, CompteIntrouvableError):
        code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, (LoginDejaPrisError, OperationInterditeError)):
        code = status.HTTP_409_CONFLICT
    elif isinstance(exc, DonneeInvalideError):
        code = status.HTTP_400_BAD_REQUEST
    else:
        raise exc
    return HTTPException(code, str(exc))


def _reponse(user: User) -> UtilisateurResponse:
    return UtilisateurResponse(
        id=user.id,
        login=user.login,
        role=user.role,
        est_active=user.est_active,
        date_creation=user.date_creation,
    )


_ERREURS = (
    PermissionError,
    CompteIntrouvableError,
    LoginDejaPrisError,
    OperationInterditeError,
    DonneeInvalideError,
)


@router.get("", response_model=list[UtilisateurResponse])
async def lister_utilisateurs(
    user: User = Depends(get_current_user),
    service: AdminService = Depends(get_admin_service),
) -> list[UtilisateurResponse]:
    """Liste des comptes (administrateur uniquement)."""
    try:
        return [_reponse(u) for u in await service.lister(user)]
    except _ERREURS as exc:
        raise _erreur_http(exc) from exc


@router.post("", response_model=UtilisateurResponse, status_code=status.HTTP_201_CREATED)
async def creer_utilisateur(
    body: CreerUtilisateurRequest,
    user: User = Depends(get_current_user),
    service: AdminService = Depends(get_admin_service),
) -> UtilisateurResponse:
    """Crée un compte avec le rôle choisi (USER, SUPERVISOR ou ADMIN)."""
    try:
        return _reponse(await service.creer(user, body.login, body.mot_de_passe, body.role))
    except _ERREURS as exc:
        raise _erreur_http(exc) from exc


@router.patch("/{user_id}/role", response_model=UtilisateurResponse)
async def changer_role(
    user_id: int,
    body: ChangerRoleRequest,
    user: User = Depends(get_current_user),
    service: AdminService = Depends(get_admin_service),
) -> UtilisateurResponse:
    """Modifie le rôle d'un compte."""
    try:
        return _reponse(await service.changer_role(user, user_id, body.role))
    except _ERREURS as exc:
        raise _erreur_http(exc) from exc


@router.patch("/{user_id}/activation", response_model=UtilisateurResponse)
async def definir_activation(
    user_id: int,
    body: ActivationRequest,
    user: User = Depends(get_current_user),
    service: AdminService = Depends(get_admin_service),
) -> UtilisateurResponse:
    """Désactive (est_active=false) ou réactive (est_active=true) un compte."""
    try:
        return _reponse(await service.definir_activation(user, user_id, body.est_active))
    except _ERREURS as exc:
        raise _erreur_http(exc) from exc


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def supprimer_utilisateur(
    user_id: int,
    user: User = Depends(get_current_user),
    service: AdminService = Depends(get_admin_service),
) -> None:
    """Supprime un compte et, avec lui, ses traitements archivés."""
    try:
        await service.supprimer(user, user_id)
    except _ERREURS as exc:
        raise _erreur_http(exc) from exc
