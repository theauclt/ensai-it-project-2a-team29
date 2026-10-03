class Singleton(type):
    """
    Métaclasse implémentant le patron de conception Singleton.

    Une classe déclarée avec `metaclass=Singleton` ne peut avoir
    qu'une seule instance partagée dans toute l'application : chaque
    appel au constructeur renvoie cette même instance.
    """

    _instances = {}  # noqa: RUF012

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]
