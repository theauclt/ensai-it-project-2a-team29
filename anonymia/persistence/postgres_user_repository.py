from ..service.business_objects.user import User
from ..service.interfaces.user_repository import UserRepository
from ..dao.db_connexion import DBConnection


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

    def _to_user(self, row: dict) -> User:
        return User(
            id=row["id"],
            login=row["username"],
            password_hash=row["mdp_hash"],
            role=row["role"],
            est_active=row["est_active"],
            date_creation=row["date_creation"],
        )