"""Accès PostgreSQL aux tentatives d'injection (implémentation de TentativeInjectionRepository)."""
from datetime import datetime

from psycopg_pool import AsyncConnectionPool

from ..service.interfaces.tentative_injection_repository import TentativeInjectionRepository


class PostgresTentativeInjectionRepository(TentativeInjectionRepository):
    """
    Implémentation de TentativeInjectionRepository pour PostgreSQL (psycopg 3, asynchrone).

    Une ligne par envoi suspect. La colonne en_attente_confirmation repère un document bloqué :
    sa confirmation met la colonne à FALSE au lieu d'ajouter une ligne.
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
        en_attente_confirmation: bool = False,
    ) -> None:
        """Insère une ligne pour cette tentative."""
        query = """
            INSERT INTO tentatives_injection
                (user_id, date_tentative, hash_document, types_injection, en_attente_confirmation)
            VALUES (%s, %s, %s, %s, %s)
        """
        async with self.__pool.connection() as conn:
            await conn.execute(
                query,
                (user_id, date_tentative, hash_document, ",".join(types_injection), en_attente_confirmation),
            )

    async def confirmer(self, user_id: int, hash_document: str) -> bool:
        """
        Passe à FALSE la dernière tentative en attente pour ce compte et ce document.

        La condition est répétée dans le UPDATE : si deux confirmations arrivent en même temps,
        une seule trouve la ligne encore en attente, l'autre compte comme une nouvelle tentative.
        """
        query = """
            UPDATE tentatives_injection SET en_attente_confirmation = FALSE
            WHERE en_attente_confirmation AND id = (
                SELECT id FROM tentatives_injection
                WHERE user_id = %s AND hash_document = %s AND en_attente_confirmation
                ORDER BY id DESC
                LIMIT 1
            )
            RETURNING id
        """
        async with self.__pool.connection() as conn:
            cur = await conn.execute(query, (user_id, hash_document))
            row = await cur.fetchone()
        return row is not None

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