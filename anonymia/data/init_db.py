"""Création et mise à jour du schéma PostgreSQL (relançable sans rien effacer)."""

from dotenv import load_dotenv

from ..persistence.dao.db_connexion import connexion_synchrone


def init_db():
    """Crée les tables (users, traitements, tentatives_injection) et ajoute les colonnes manquantes."""
    # Le bloc `with connection` valide tout à sa sortie, ou annule tout en cas d'erreur
    with connexion_synchrone() as connection, connection.cursor() as cursor:
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

        # user_id peut être NULL : supprimer un compte ne supprime pas ses traces d'audit
        # (ON DELETE SET NULL), elles restent consultables par les superviseurs.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traitements (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id INTEGER,
                date_traitement TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                hash_document VARCHAR(255) NOT NULL,
                strategie_anonymisation VARCHAR(255) NOT NULL,
                detecteurs_contributeurs VARCHAR(255) NOT NULL,
                nb_pii_detectees INTEGER NOT NULL,
                injection_suspectee BOOLEAN NOT NULL DEFAULT FALSE,
                types_pii TEXT NOT NULL DEFAULT '',
                juge_statut VARCHAR(20),
                juge_type VARCHAR(50),

                CONSTRAINT fk_traitements_user
                    FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE SET NULL
            );
        """)
        cursor.execute("""
            ALTER TABLE traitements
            ADD COLUMN IF NOT EXISTS injection_suspectee BOOLEAN NOT NULL DEFAULT FALSE;
        """)
        cursor.execute("""
            ALTER TABLE traitements
            ADD COLUMN IF NOT EXISTS types_pii TEXT NOT NULL DEFAULT '';
        """)
        cursor.execute("""
            ALTER TABLE traitements
            ADD COLUMN IF NOT EXISTS juge_statut VARCHAR(20),
            ADD COLUMN IF NOT EXISTS juge_type VARCHAR(50);
        """)
        # Tentatives d'injection de prompt : une ligne par envoi suspect. Un document bloqué
        # (en_attente_confirmation) puis confirmé ne fait qu'une ligne. Seule l'empreinte du
        # document est gardée, jamais son contenu.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tentatives_injection (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id INTEGER,
                date_tentative TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                hash_document VARCHAR(64) NOT NULL,
                types_injection TEXT NOT NULL DEFAULT '',
                en_attente_confirmation BOOLEAN NOT NULL DEFAULT FALSE,

                CONSTRAINT fk_tentatives_user
                    FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE SET NULL
            );
        """)
        # Tables créées par la première version : un même document ne comptait qu'une fois
        # (contrainte UNIQUE). Désormais chaque envoi compte.
        cursor.execute("""
            ALTER TABLE tentatives_injection DROP CONSTRAINT IF EXISTS uq_tentative_user_document;
        """)
        cursor.execute("""
            ALTER TABLE tentatives_injection
            ADD COLUMN IF NOT EXISTS en_attente_confirmation BOOLEAN NOT NULL DEFAULT FALSE;
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_tentatives_user_document
            ON tentatives_injection (user_id, hash_document);
        """)
        # Bases créées avant ce changement : on remplace la clé étrangère en cascade.
        # Sans danger si on la relance (la contrainte est supprimée puis recréée).
        cursor.execute("""
            ALTER TABLE traitements ALTER COLUMN user_id DROP NOT NULL;
        """)
        cursor.execute("""
            ALTER TABLE traitements DROP CONSTRAINT IF EXISTS fk_traitements_user;
        """)
        cursor.execute("""
            ALTER TABLE traitements
            ADD CONSTRAINT fk_traitements_user
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
        """)


if __name__ == "__main__":
    load_dotenv()  # lit POSTGRES_* depuis le fichier .env
    init_db()
    print("Tables users, traitements et tentatives_injection prêtes.")