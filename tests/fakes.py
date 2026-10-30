from anonymia.service.business_objects.audit_entry import AuditEntry
from anonymia.service.business_objects.user import User
from anonymia.service.interfaces.archive_repository import ArchiveRepository
from anonymia.service.interfaces.user_repository import UserRepository


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


class FakeUserRepository(UserRepository):
    """Comptes gardés en mémoire : remplace PostgreSQL dans les tests."""

    def __init__(self, users: list[User] | None = None) -> None:
        self.users = {u.login: u for u in users or []}

    async def find_by_login(self, login: str) -> User | None:
        return self.users.get(login)