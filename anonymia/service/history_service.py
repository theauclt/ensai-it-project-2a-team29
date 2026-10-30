from datetime import UTC, datetime

from .business_objects.audit_entry import AuditEntry
from .business_objects.user import User
from .interfaces.archive_repository import ArchiveRepository


def _as_utc(date: datetime) -> datetime:
    """PostgreSQL renvoie des dates sans fuseau (UTC) : on les rend comparables."""
    return date if date.tzinfo is not None else date.replace(tzinfo=UTC)


class HistoryService:
    """Consultation de l'historique des traitements, réservée à certains rôles (F4)."""

    ROLES_AUTORISES = frozenset({"SUPERVISOR", "ADMIN"})

    def __init__(self, archive_repo: ArchiveRepository):
        self._archive_repo = archive_repo

    async def get_history(
        self,
        requester: User,
        user_id: int | None = None,
        date_debut: datetime | None = None,
        date_fin: datetime | None = None,
    ) -> list[AuditEntry]:
        """Renvoie les traitements (du plus récent au plus ancien), filtrés si demandé."""
        # Défense en profondeur : le contrôle est ici, pas seulement dans la route
        if requester.role not in self.ROLES_AUTORISES:
            raise PermissionError(
                "La consultation de l'historique est réservée aux superviseurs "
                "et aux administrateurs"
            )

        if user_id is not None:
            entries = await self._archive_repo.find_by_user(user_id)
        else:
            entries = await self._archive_repo.find_all()

        if date_debut is not None:
            entries = [e for e in entries if _as_utc(e.date_traitement) >= _as_utc(date_debut)]
        if date_fin is not None:
            entries = [e for e in entries if _as_utc(e.date_traitement) <= _as_utc(date_fin)]

        return sorted(entries, key=lambda e: _as_utc(e.date_traitement), reverse=True)