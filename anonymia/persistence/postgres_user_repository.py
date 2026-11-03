from ..service.business_objects.user import User
from ..service.interfaces.user_repository import UserRepository
from .dao.db_connexion import DBConnection


class PostgresUserRepository(UserRepository):
    """
    Implémentation concrète de UserRepository avec psycopg2,
    sans ORM, pour PostgreSQL.
    """

    def __init__(self) -> None:
        self.__connection = DBConnection().connection

    async def find_by_login(self, login: str) -> User | None:
        # pour trouver un user
        query = "SELECT * FROM users WHERE username = %s"
        with self.__connection.cursor() as cur:
            cur.execute(query, (login,))
            row = cur.fetchone()

        if row is None:
            return None

        return self._to_user(row)

    async def find_by_id(self, user_id: int) -> User | None:
        with self.__connection.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
        return None if row is None else self._to_user(row)

    async def find_all(self) -> list[User]:
        with self.__connection.cursor() as cur:
            cur.execute("SELECT * FROM users ORDER BY id")
            rows = cur.fetchall()
        return [self._to_user(row) for row in rows]

    async def create(self, login: str, password_hash: str, role: str) -> None:
        self._write(
            "INSERT INTO users (username, mdp_hash, role) VALUES (%s, %s, %s)",
            (login, password_hash, role),
        )

    async def update_role(self, user_id: int, role: str) -> None:
        self._write("UPDATE users SET role = %s WHERE id = %s", (role, user_id))

    async def set_active(self, user_id: int, est_active: bool) -> None:
        self._write("UPDATE users SET est_active = %s WHERE id = %s", (est_active, user_id))

    async def delete(self, user_id: int) -> None:
        self._write("DELETE FROM users WHERE id = %s", (user_id,))

    def _write(self, query: str, params: tuple) -> None:
        """Exécute une écriture : commit si elle réussit, rollback sinon."""
        try:
            with self.__connection.cursor() as cur:
                cur.execute(query, params)
            self.__connection.commit()
        except Exception:
            self.__connection.rollback()
            raise

    def _to_user(self, row: dict) -> User:
        return User(
            id=row["id"],
            login=row["username"],
            password_hash=row["mdp_hash"],
            role=row["role"],
            est_active=row["est_active"],
            date_creation=row["date_creation"],
        )