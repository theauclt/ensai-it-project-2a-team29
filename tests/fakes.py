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

    async def find_by_id(self, user_id: int) -> User | None:
        return next((u for u in self.users.values() if u.id == user_id), None)

    async def find_all(self) -> list[User]:
        return sorted(self.users.values(), key=lambda u: u.id)

    async def create(self, login: str, password_hash: str, role: str) -> None:
        next_id = max((u.id for u in self.users.values()), default=0) + 1
        self.users[login] = User(next_id, login, password_hash, role)

    async def update_role(self, user_id: int, role: str) -> None:
        (await self.find_by_id(user_id)).role = role

    async def set_active(self, user_id: int, est_active: bool) -> None:
        (await self.find_by_id(user_id)).est_active = est_active

    async def delete(self, user_id: int) -> None:
        user = await self.find_by_id(user_id)
        del self.users[user.login]
