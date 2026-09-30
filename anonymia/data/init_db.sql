-- Suppression des tables si elles existent déjà
DROP TABLE IF EXISTS traitements;
DROP TABLE IF EXISTS users;


-- =========================
-- TABLE USERS
-- =========================

CREATE TABLE users (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    mdp_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    est_active BOOLEAN NOT NULL DEFAULT TRUE,
    date_creation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- =========================
-- TABLE TRAITEMENTS
-- =========================

CREATE TABLE traitements (
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