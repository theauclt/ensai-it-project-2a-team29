from datetime import datetime


class AuditEntry:
    """
    Entrée d'audit persistée par ArchiveRepository (F4).

    Reflète la table `traitements` du schéma BDD : uniquement des
    métadonnées, jamais le contenu du document ni les PII détectées
    individuellement.
    """

    def __init__(
        self,
        user_id: str,
        date_traitement: datetime,
        hash_document: str,
        strategie_anonymisation: str,
        detecteurs_contributeurs: str,
        nb_pii_detectees: int,
        id: int | None = None,
    ) -> None:
        self.id = id
        self.user_id = user_id
        self.date_traitement = date_traitement
        self.hash_document = hash_document
        self.strategie_anonymisation = strategie_anonymisation
        self.detecteurs_contributeurs = detecteurs_contributeurs
        self.nb_pii_detectees = nb_pii_detectees