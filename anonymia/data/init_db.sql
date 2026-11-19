-- Suppression des tables si elles existent déjà
DROP TABLE IF EXISTS tentatives_injection;
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
    injection_suspectee BOOLEAN NOT NULL DEFAULT FALSE,
    types_pii TEXT NOT NULL DEFAULT '',
    juge_statut VARCHAR(20),
    juge_type VARCHAR(50),

    CONSTRAINT fk_traitements_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);


-- =========================
-- TABLE TENTATIVES_INJECTION
-- =========================
-- Une ligne par envoi d'un document suspect d'injection de prompt. Un document bloqué
-- (en_attente_confirmation) puis confirmé ne fait qu'une ligne. Seule l'empreinte du document
-- est gardée. 3 tentatives : compte signalé ; 10 : compte désactivé.

CREATE TABLE tentatives_injection (
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

CREATE INDEX idx_tentatives_user_document ON tentatives_injection (user_id, hash_document);
