from datetime import datetime


class User:
    """
    Représente un compte utilisateur d'Anonymia.

    Le mot de passe n'est jamais stocké en clair : password_hash
    contient uniquement son empreinte, vérifiée par AuthentificationService.
    Le rôle détermine les droits d'accès : utilisateur,
    superviseur ou administrateur.
    """

    def __init__(
        self,
        id: str,
        login: str,
        password_hash: str,
        role: str,
        est_active: bool = True,
        date_creation: datetime | None = None,
        tentatives_injection: int = 0,
        comportement_dangereux: bool = False,
    ):
        """
        tentatives_injection et comportement_dangereux ne sont pas des colonnes de la table
        users : SurveillanceInjections les renseigne pour la liste des comptes.
        """
        self.id = id
        self.login = login
        self.password_hash = password_hash
        self.role = role
        self.est_active = est_active
        self.date_creation = date_creation
        self.tentatives_injection = tentatives_injection
        self.comportement_dangereux = comportement_dangereux