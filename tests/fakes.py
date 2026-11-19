from contextlib import asynccontextmanager
from datetime import datetime

from anonymia.service.business_objects.audit_entry import AuditEntry
from anonymia.service.business_objects.user import User
from anonymia.service.interfaces.archive_repository import ArchiveRepository
from anonymia.service.interfaces.tentative_injection_repository import TentativeInjectionRepository
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


class FakeTentativeInjectionRepository(TentativeInjectionRepository):
    """Tentatives d'injection gardées en mémoire, un document compté une fois par compte."""

    def __init__(self) -> None:
        self.tentatives: dict[tuple[int, str], tuple[list[str], datetime]] = {}

    async def enregistrer(
        self, user_id: int, hash_document: str, types_injection: list[str], date_tentative: datetime
    ) -> None:
        self.tentatives.setdefault((user_id, hash_document), (list(types_injection), date_tentative))

    async def compter(self, user_id: int) -> int:
        return sum(1 for uid, _ in self.tentatives if uid == user_id)

    async def compter_par_utilisateur(self) -> dict[int, int]:
        compteurs: dict[int, int] = {}
        for uid, _ in self.tentatives:
            compteurs[uid] = compteurs.get(uid, 0) + 1
        return compteurs


class FakeCurseur:
    """Curseur asynchrone : renvoie les lignes préparées par le test."""

    def __init__(self, connexion: "FakeConnexion") -> None:
        self.c = connexion

    async def fetchone(self):
        return self.c.ligne

    async def fetchall(self):
        return self.c.lignes


class FakeConnexion:
    """Connexion PostgreSQL asynchrone factice : enregistre les requêtes reçues."""

    def __init__(self) -> None:
        self.requetes: list[tuple[str, tuple | None]] = []
        self.commits = self.rollbacks = 0
        self.ligne = None
        self.lignes: list = []
        self.echec = False

    async def execute(self, query, params=None):
        if self.echec:
            raise RuntimeError("erreur SQL")
        self.requetes.append((" ".join(query.split()), params))
        return FakeCurseur(self)


class FakePool:
    """
    Pool de connexions factice, qui reprend la règle de psycopg_pool : la transaction est
    validée à la sortie de `async with pool.connection()`, ou annulée si une erreur l'a
    interrompue. Les dépôts n'ont donc aucun commit à écrire eux-mêmes.
    """

    def __init__(self) -> None:
        self.connexion = FakeConnexion()

    @asynccontextmanager
    async def connection(self):
        try:
            yield self.connexion
        except BaseException:
            self.connexion.rollbacks += 1
            raise
        else:
            self.connexion.commits += 1
