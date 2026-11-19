"""
Accès à PostgreSQL avec psycopg 3.

L'API utilise un pool de connexions asynchrone : une requête SQL n'arrête plus les autres
traitements, et une connexion perdue est remplacée par le pool. Les scripts (init_db,
create_user) n'ont pas besoin d'asynchrone et utilisent une connexion ordinaire.

Les paramètres viennent des variables d'environnement POSTGRES_* (KeyError si l'une manque).
"""
import os

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

# Un pool petit suffit : l'application a peu d'écritures et des requêtes courtes
POOL_MIN = 1
POOL_MAX = 5


def parametres_connexion() -> dict:
    """
    Paramètres de connexion à PostgreSQL, lus dans l'environnement.

    La session est réglée sur UTC : les colonnes de dates sont des TIMESTAMP sans fuseau,
    et l'API les relit en les considérant comme de l'UTC.
    """
    return {
        "host": os.environ["POSTGRES_HOST"],
        "port": os.environ["POSTGRES_PORT"],
        "dbname": os.environ["POSTGRES_DATABASE"],
        "user": os.environ["POSTGRES_USER"],
        "password": os.environ["POSTGRES_PASSWORD"],
        "options": f"-c search_path={os.environ['POSTGRES_SCHEMA']} -c timezone=UTC",
    }


def construire_pool() -> AsyncConnectionPool:
    """
    Pool de connexions asynchrone, non ouvert : il faut appeler `await pool.open()`.

    Chaque ligne lue est un dictionnaire (colonne -> valeur). Le bloc
    `async with pool.connection()` valide la transaction à sa sortie, ou l'annule si une
    exception l'a interrompue : les dépôts n'ont pas à écrire de commit ni de rollback.

    Le pool vérifie qu'une connexion répond avant de la prêter : si la base a redémarré ou
    coupé la connexion, il en ouvre une nouvelle au lieu de faire échouer la requête.
    """
    return AsyncConnectionPool(
        conninfo="",
        kwargs={**parametres_connexion(), "row_factory": dict_row},
        min_size=POOL_MIN,
        max_size=POOL_MAX,
        check=AsyncConnectionPool.check_connection,
        open=False,
    )


def connexion_synchrone() -> psycopg.Connection:
    """
    Connexion ordinaire pour les scripts. À utiliser dans un bloc `with` : la transaction
    est validée à la sortie du bloc (ou annulée en cas d'erreur), puis la connexion fermée.
    """
    return psycopg.connect(**parametres_connexion())
