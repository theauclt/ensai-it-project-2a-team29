from abc import ABC, abstractmethod

from ..business_objects.audit_entry import AuditEntry


class ArchiveRepository(ABC):
    """
    Interface de persistance pour les entrées d'audit (F4).

    Réalisée par PostgresArchiveRepository (dao/). Ne manipule jamais
    le contenu du document ni les PII détectées individuellement,
    seulement les métadonnées du traitement (hash, date, nombre de
    PII, stratégie, détecteurs ayant contribué).
    """

    @abstractmethod
    async def save(self, entry: AuditEntry) -> None:
        """Enregistre une nouvelle entrée d'audit."""
        pass

    @abstractmethod
    async def find_by_user(self, user_id: str) -> list[AuditEntry]:
        """Retourne les entrées d'audit d'un utilisateur donné."""
        pass

    @abstractmethod
    async def find_all(self) -> list[AuditEntry]:
        """Retourne l'ensemble des entrées d'audit (superviseur/admin)."""
        pass