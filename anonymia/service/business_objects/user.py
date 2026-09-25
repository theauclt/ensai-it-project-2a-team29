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
        role: str
    ):
        """Constructor"""
        self.id = id
        self.login = login
        self.password_hash = password_hash
        self.role = role