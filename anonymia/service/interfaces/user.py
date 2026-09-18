class User:
    """
    blabla description
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