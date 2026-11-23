"""Accès PostgreSQL aux utilisateurs (implémentation de UserRepository)."""
from psycopg_pool import AsyncConnectionPool

from ..service.business_objects.user import User
from ..service.interfaces.user_repository import UserRepository


class PostgresUserRepository(UserRepository):
    """
    Implémentation concrète de UserRepository avec psycopg 3 (asynchrone),
    sans ORM, pour PostgreSQL.
    """

    def __init__(self, pool: AsyncConnectionPool) -> None:
        """pool : pool de connexions asynchrone partagé avec les autres dépôts."""
        self.__pool = pool

    async def find_by_login(self, login: str) -> User | None:
        """Renvoie l'utilisateur ayant ce login, ou None s'il n'existe pas."""
        query = "SELECT * FROM users WHERE username = %s"
        async with self.__pool.connection() as conn:
            cur = await conn.execute(query, (login,))
            row = await cur.fetchone()

        if row is None:
            return None

        return self._to_user(row)

    async def find_by_id(self, user_id: int) -> User | None:
        """Renvoie l'utilisateur ayant cet identifiant, ou None s'il n'existe pas."""
        async with self.__pool.connection() as conn:
            cur = await conn.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = await cur.fetchone()
        return None if row is None else self._to_user(row)

    async def find_all(self) -> list[User]:
        """Renvoie tous les utilisateurs, triés par identifiant."""
        async with self.__pool.connection() as conn:
            cur = await conn.execute("SELECT * FROM users ORDER BY id")
            rows = await cur.fetchall()
        return [self._to_user(row) for row in rows]

    async def create(self, login: str, password_hash: str, role: str) -> None:
        """Crée un utilisateur (le mot de passe est déjà haché)."""
        await self._write(
            "INSERT INTO users (username, mdp_hash, role) VALUES (%s, %s, %s)",
            (login, password_hash, role),
        )

    async def update_role(self, user_id: int, role: str) -> None:
        """Change le rôle d'un utilisateur."""
        await self._write("UPDATE users SET role = %s WHERE id = %s", (role, user_id))

    async def set_active(self, user_id: int, est_active: bool) -> None:
        """Active ou désactive un compte."""
        await self._write("UPDATE users SET est_active = %s WHERE id = %s", (est_active, user_id))

    async def delete(self, user_id: int) -> None:
        """Supprime un utilisateur (son historique est conservé, user_id devient vide)."""
        await self._write("DELETE FROM users WHERE id = %s", (user_id,))

    async def _write(self, query: str, params: tuple) -> None:
        """Exécute une écriture : le pool valide la transaction si elle réussit, l'annule sinon."""
        async with self.__pool.connection() as conn:
            await conn.execute(query, params)

    def _to_user(self, row: dict) -> User:
        """Transforme une ligne de la table users en objet User."""
        return User(
            id=row["id"],
            login=row["username"],
            password_hash=row["mdp_hash"],
            role=row["role"],
            est_active=row["est_active"],
            date_creation=row["date_creation"],
        )