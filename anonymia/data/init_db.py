from ..dao.db_connexion import DBConnection


def init_db():
    connection = DBConnection().connection

    with connection.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                mdp_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                est_active BOOLEAN NOT NULL DEFAULT TRUE,
                date_creation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traitements (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id INTEGER NOT NULL,
                date_traitement TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                hash_document VARCHAR(255) NOT NULL,
                strategie_anonymisation VARCHAR(255) NOT NULL,
                detecteurs_contributeurs VARCHAR(255) NOT NULL,
                nb_pii_detectees INTEGER NOT NULL,

                CONSTRAINT fk_traitements_user
                    FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );
        """)

    connection.commit()


if __name__ == "__main__":
    init_db()