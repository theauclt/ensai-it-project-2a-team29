from datetime import UTC, date, datetime, time

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..service.business_objects.user import User
from ..service.history_service import HistoryService
from .providers import get_history_service
from .schemas import TraitementResponse
from .security import get_current_user

router = APIRouter(prefix="/journaux", tags=["Journalisation"])


def _en_utc(date: datetime) -> datetime:
    return date if date.tzinfo is not None else date.replace(tzinfo=UTC)


@router.get("", response_model=list[TraitementResponse])
async def lister_traitements(
    utilisateur: str | None = Query(None, description="Login de l'utilisateur"),
    date_debut: date | None = Query(None, description="Premier jour inclus (AAAA-MM-JJ)"),
    date_fin: date | None = Query(None, description="Dernier jour inclus (AAAA-MM-JJ)"),
    user: User = Depends(get_current_user),
    service: HistoryService = Depends(get_history_service),
) -> list[TraitementResponse]:
    """Historique des traitements, réservé aux superviseurs et administrateurs."""
    # Les jours sont inclusifs : de 00:00 du premier jour à 23:59:59 du dernier
    debut = datetime.combine(date_debut, time.min, tzinfo=UTC) if date_debut else None
    fin = datetime.combine(date_fin, time.max, tzinfo=UTC) if date_fin else None

    try:
        entries = await service.get_history(user, utilisateur, debut, fin)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    return [
        TraitementResponse(
            id=e.id,
            user_id=e.user_id,
            # PostgreSQL renvoie des dates sans fuseau : on précise qu'elles sont en UTC
            date_traitement=_en_utc(e.date_traitement),
            hash_document=e.hash_document,
            strategie_anonymisation=e.strategie_anonymisation,
            detecteurs_contributeurs=e.detecteurs_contributeurs,
            nb_pii_detectees=e.nb_pii_detectees,
        )
        for e in entries
    ]