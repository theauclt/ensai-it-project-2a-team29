from datetime import datetime

from psycopg_pool import AsyncConnectionPool

from ..service.interfaces.tentative_injection_repository import TentativeInjectionRepository


class PostgresTentativeInjectionRepository(TentativeInjectionRepository):
    """
    Implémentation de TentativeInjectionRepository pour PostgreSQL (psycopg 3, asynchrone).

    La contrainte UNIQUE (user_id, hash_document) de la table garantit qu'un même document
    ne compte qu'une fois par compte, même si deux requêtes arrivent en même temps.
    """

    def __init__(self, pool: AsyncConnectionPool) -> None:
        """pool : pool de connexions partagé avec les autres dépôts."""
        self.__pool = pool

    async def enregistrer(
        self,
        user_id: int,
        hash_document: str,
        types_injection: list[str],
        date_tentative: datetime,
    ) -> None:
        """Insère la tentative ; ON CONFLICT ignore un document déjà compté pour ce compte."""
        query = """
            INSERT INTO tentatives_injection (user_id, date_tentative, hash_document, types_injection)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (user_id, hash_document) DO NOTHING
        """
        async with self.__pool.connection() as conn:
            await conn.execute(
                query, (user_id, date_tentative, hash_document, ",".join(types_injection))
            )

    async def compter(self, user_id: int) -> int:
        """Nombre de tentatives enregistrées pour ce compte."""
        async with self.__pool.connection() as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) AS nb FROM tentatives_injection WHERE user_id = %s", (user_id,)
            )
            row = await cur.fetchone()
        return int(row["nb"]) if row else 0

    async def compter_par_utilisateur(self) -> dict[int, int]:
        """Une seule requête pour toute la liste des comptes (page Administration)."""
        query = """
            SELECT user_id, COUNT(*) AS nb
            FROM tentatives_injection
            WHERE user_id IS NOT NULL
            GROUP BY user_id
        """
        async with self.__pool.connection() as conn:
            cur = await conn.execute(query)
            rows = await cur.fetchall()
        return {row["user_id"]: int(row["nb"]) for row in rows}
