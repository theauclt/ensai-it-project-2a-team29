from ..service.business_objects.audit_entry import AuditEntry
from ..service.interfaces.archive_repository import ArchiveRepository
from .db_connexion import DBConnection


class PostgresArchiveRepository(ArchiveRepository):
    """
    Implémentation concrète de ArchiveRepository pour PostgreSQL.
    """

    def __init__(self) -> None:
        self.__connection = DBConnection().connection

    async def save(self, entry: AuditEntry) -> None:
        # pour enregistrer un traitemen† dans la bdd
        query = """
            INSERT INTO traitements (
                user_id, date_traitement, hash_document,
                strategie_anonymisation, detecteurs_contributeurs,
                nb_pii_detectees
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        with self.__connection.cursor() as cur:
            cur.execute(
                query,
                (
                    entry.user_id,
                    entry.date_traitement,
                    entry.hash_document,
                    entry.strategie_anonymisation,
                    entry.detecteurs_contributeurs,
                    entry.nb_pii_detectees,
                ),
            )
        self.__connection.commit()

    async def find_by_user(self, user_id: str) -> list[AuditEntry]:
        # pour quand un superviseur veut filtrer par user 
        query = "SELECT * FROM traitements WHERE user_id = %s"
        with self.__connection.cursor() as cur:
            cur.execute(query, (user_id,))
            rows = cur.fetchall()
        return [self._to_entry(row) for row in rows]

    async def find_all(self) -> list[AuditEntry]:
        # pour voir toute l'historoque complet 
        query = "SELECT * FROM traitements"
        with self.__connection.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
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
        )