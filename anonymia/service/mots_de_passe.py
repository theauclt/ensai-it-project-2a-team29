import bcrypt

MOT_DE_PASSE_MIN = 8


def hasher_mot_de_passe(mot_de_passe: str) -> str:
    """Empreinte bcrypt (sel aléatoire intégré) : seule cette empreinte est stockée."""
    return bcrypt.hashpw(mot_de_passe.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
