"""
Crée un compte (par exemple le premier administrateur).

Usage (depuis la racine du dépôt) :
    python -m scripts.create_user <login> <role>
    python -m scripts.create_user admin ADMIN

Le mot de passe est demandé au clavier : il n'apparaît ni à l'écran ni dans
l'historique du terminal. Rôles possibles : USER, SUPERVISOR, ADMIN.
"""
import getpass
import sys

import bcrypt
import psycopg2
from dotenv import load_dotenv

load_dotenv()  # doit précéder l'import de DBConnection (lit POSTGRES_* à la création)

from anonymia.persistence.dao.db_connexion import DBConnection

ROLES = ("USER", "SUPERVISOR", "ADMIN")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2].upper() not in ROLES:
        print(f"Usage : python -m scripts.create_user <login> <{'|'.join(ROLES)}>")
        return 1

    login, role = sys.argv[1], sys.argv[2].upper()
    password = getpass.getpass("Mot de passe : ")
    if len(password) < 8:
        print("Mot de passe trop court (8 caractères minimum).")
        return 1
    if password != getpass.getpass("Confirmation : "):
        print("Les deux mots de passe sont différents.")
        return 1

    # bcrypt génère lui-même un sel aléatoire, intégré dans le hash stocké
    mdp_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    connection = DBConnection().connection
    try:
        with connection.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, mdp_hash, role) VALUES (%s, %s, %s)",
                (login, mdp_hash, role),
            )
        connection.commit()
    except psycopg2.Error as exc:
        print(f"Création impossible : {type(exc).__name__} (login déjà pris ?)")
        return 1

    print(f"Compte '{login}' créé avec le rôle {role}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())