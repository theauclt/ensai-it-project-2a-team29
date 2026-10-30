from anonymia.service.business_objects.audit_entry import AuditEntry
from anonymia.service.interfaces.archive_repository import ArchiveRepository


class FakeArchiveRepository(ArchiveRepository):
    """Historique gardé en mémoire : remplace PostgreSQL dans les tests."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    async def save(self, entry: AuditEntry) -> None:
        entry.id = len(self.entries) + 1
        self.entries.append(entry)

    async def find_by_user(self, user_id: int) -> list[AuditEntry]:
        return [e for e in self.entries if e.user_id == user_id]

    async def find_all(self) -> list[AuditEntry]:
        return list(self.entries)