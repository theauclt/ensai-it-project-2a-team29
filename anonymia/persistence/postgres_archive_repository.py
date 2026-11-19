from psycopg_pool import AsyncConnectionPool

from ..service.business_objects.audit_entry import AuditEntry
from ..service.interfaces.archive_repository import ArchiveRepository


class PostgresArchiveRepository(ArchiveRepository):
    """
    Implémentation concrète de ArchiveRepository pour PostgreSQL (psycopg 3, asynchrone).
    """

    def __init__(self, pool: AsyncConnectionPool) -> None:
        self.__pool = pool

    async def save(self, entry: AuditEntry) -> None:
        # pour enregistrer un traitemen† dans la bdd
        query = """
            INSERT INTO traitements (
                user_id, date_traitement, hash_document,
                strategie_anonymisation, detecteurs_contributeurs,
                nb_pii_detectees, injection_suspectee, types_pii,
                juge_statut, juge_type
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        # le pool valide la transaction à la sortie du bloc (ou l'annule si une erreur survient)
        async with self.__pool.connection() as conn:
            await conn.execute(
                query,
                (
                    entry.user_id,
                    entry.date_traitement,
                    entry.hash_document,
                    entry.strategie_anonymisation,
                    entry.detecteurs_contributeurs,
                    entry.nb_pii_detectees,
                    entry.injection_suspectee,
                    entry.types_pii,
                    entry.juge_statut,
                    entry.juge_type,
                ),
            )

    async def find_by_user(self, user_id: int) -> list[AuditEntry]:
        # pour quand un superviseur veut filtrer par user
        query = "SELECT * FROM traitements WHERE user_id = %s"
        async with self.__pool.connection() as conn:
            cur = await conn.execute(query, (user_id,))
            rows = await cur.fetchall()
        return [self._to_entry(row) for row in rows]

    async def find_all(self) -> list[AuditEntry]:
        # pour voir toute l'historoque complet
        query = "SELECT * FROM traitements"
        async with self.__pool.connection() as conn:
            cur = await conn.execute(query)
            rows = await cur.fetchall()
        return [self._to_entry(row) for row in rows]

    def _to_entry(self, row: dict) -> AuditEntry:
        # methode privée
        # utilisée en interne par find_by_user et find_all seulement
        # Elle sert de traducteur : une ligne renvoyée par PostgreSQL est juste un dictionnaire brut
        return AuditEntry(
            id=row["id"],
            user_id=row["user_id"],
            date_traitement=row["date_traitement"],
            hash_document=row["hash_document"],
            strategie_anonymisation=row["strategie_anonymisation"],
            detecteurs_contributeurs=row["detecteurs_contributeurs"],
            nb_pii_detectees=row["nb_pii_detectees"],
            injection_suspectee=row["injection_suspectee"],
            types_pii=row.get("types_pii") or "",
            juge_statut=row.get("juge_statut"),
            juge_type=row.get("juge_type"),
        )