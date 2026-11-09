# Anonymia

Anonymia reçoit un texte, détecte les données personnelles (e-mail, téléphone, NIR, IBAN,
plaques, noms, lieux, dates de naissance...) avec des expressions régulières, un NER spaCy
(facultatif) et un LLM, puis renvoie le texte caviardé (masquage ou pseudonymisation).
Chaque traitement est archivé (hash du document, stratégie, nombre et types de PII, verdicts
anti-injection) : jamais le contenu. Les superviseurs et administrateurs consultent l'historique.

Projet ENSAI 2A, groupe 29. Ce fichier suffit pour installer, lancer et tester l'application.
Anonymia est une aide au caviardage, pas une garantie : une relecture humaine reste nécessaire.

## 1. Prérequis

- Python 3.12 ou plus récent, Git
- Une base PostgreSQL (celle du Datalab)
- Facultatif : une clé pour le LLM du Datalab. Sans elle, l'API fonctionne avec les expressions
  régulières seules (`LLM_ENABLED=false`).

## 2. Installation

Depuis la racine du dépôt (le dossier qui contient `pyproject.toml`) :

    python -m venv .venv
    source .venv/bin/activate          # Windows : .venv\Scripts\activate
    pip install -e ".[dev]"

À refaire seulement si `pyproject.toml` change. Réactiver l'environnement à chaque nouveau terminal.
Détecteur NER (facultatif) : `pip install spacy && python -m spacy download fr_core_news_lg`.

## 3. Configuration

    cp .env.exemple .env

Le fichier `.env` est ignoré par Git : ne jamais le partager ni le commiter.

| Variable | Rôle |
|---|---|
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DATABASE`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_SCHEMA` | Base de données |
| `JWT_SECRET` | Secret de signature des jetons, **32 caractères minimum** (sans lui, l'API refuse de démarrer) |
| `ADMIN_LOGIN`, `ADMIN_PASSWORD` | Compte administrateur initial, créé au démarrage s'il n'existe pas (8 caractères et 72 octets maximum) |
| `LLM_ENABLED` | `false` : expressions régulières seules |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `LLM_TIMEOUT` | LLM (Datalab : `https://llm.lab.sspcloud.fr/api`, modèle `qwen3-8-27b`) |
| `LLM_JUDGE_ENABLED`, `LLM_JUDGE_MODEL` | Juge d'injection LLM (actif avec le LLM, il double les appels) |
| `NER_ENABLED`, `SPACY_MODEL` | Détecteur NER spaCy (désactivé par défaut) |

Générer un secret JWT :

    python -c "import secrets; print(secrets.token_urlsafe(48))"

Clé du LLM du Datalab : se connecter sur https://llm.lab.sspcloud.fr/, copier la clé d'accès du
profil dans `LLM_API_KEY`. Règle du projet : jamais d'API LLM commerciale sur du contenu réel.

## 4. Préparer la base

    python -m anonymia.data.init_db

À relancer après chaque `git pull` : la commande ajoute les colonnes nouvelles sans rien
supprimer. Sans cela, l'API répond 500 (`UndefinedColumn`).

Comptes : l'administrateur est créé au démarrage de l'API si `ADMIN_LOGIN` et `ADMIN_PASSWORD`
sont dans `.env`. Sinon, ou pour les autres comptes (mot de passe demandé au clavier) :

    python -m scripts.create_user admin ADMIN
    python -m scripts.create_user sup SUPERVISOR
    python -m scripts.create_user alice USER
    python -m scripts.check_db admin <mot_de_passe>     # vérifie base et authentification

## 5. Lancer l'API

    uvicorn anonymia.main:app --reload

Documentation interactive : http://localhost:8000/docs. Sur le Datalab (VSCode), l'API passe par
un proxy : ajouter `--root-path /proxy/8000`, puis ouvrir `.../proxy/8000/docs`.

## 6. Interface Streamlit

Dans un second terminal, **après** l'API :

    source .venv/bin/activate
    python -m streamlit run interface/app.py

Pages selon le rôle : Caviardage (tous), Tableau de bord, Historique (SUPERVISOR et ADMIN),
Administration (ADMIN). L'interface ne contient aucune logique : tout passe par l'API.

## 7. Utiliser l'API depuis `/docs`

1. `POST /auth/connexion` avec `{"login": "...", "mot_de_passe": "..."}` : copier `access_token`.
2. Cliquer sur « Authorize », coller le jeton **sans** « Bearer ». Il expire après 30 minutes.
3. Appeler les routes :

| Route | Rôle | Corps |
|---|---|---|
| `POST /documents/caviarder` | tous | `{"contenu": "...", "strategie": "masking"}` (ou `pseudonymization`) ; `"confirmer": true` si une injection est suspectée |
| `POST /documents/analyser` | tous | `{"contenu": "..."}` : PII avec position et confiance, rien n'est archivé |
| `GET /documents/strategies` | tous | |
| `GET /journaux` | SUPERVISOR, ADMIN | filtres : `utilisateur`, `date_debut`, `date_fin` |
| `/admin/utilisateurs...` | ADMIN | liste, création, rôle, activation, suppression |

Il n'y a pas d'inscription libre : l'administrateur crée les comptes. Le rôle est lu dans le
jeton : 403 pour une route interdite au rôle.

Exemples : `{"contenu": "Écrire à jean@mail.fr ou au 06 12 34 56 78.", "strategie": "masking"}`
renvoie `Écrire à [EMAIL_1] ou au [TEL_1].` ; en pseudonymisation, `utilisateur1@example.com`
et `06 00 00 00 01`. Une même valeur reçoit toujours le même marqueur.

Erreurs attendues : 401 sans jeton ou mauvais mot de passe, 403 mauvais rôle, 400 stratégie
inconnue, 422 contenu vide ou mot de passe de plus de 72 octets.

## 8. Tests et qualité

    ruff check .
    pytest --cov=anonymia --cov-branch --cov-report=term-missing

Sans base ni LLM réels. Avant chaque commit, les deux commandes doivent passer.

## 9. Évaluation sur le corpus de test

    python -m scripts.evaluer_corpus corpus-test            # expressions régulières et filtre d'injection
    python -m scripts.evaluer_corpus corpus-test --llm      # avec le LLM
    python -m scripts.evaluer_juge corpus-test              # juge d'injection LLM (68 appels au LLM)

Les tableaux (`metriques.md`, `metriques_juge.md`) sont écrits dans le dossier `--sortie`.

## 10. Sécurité : ce qu'il faut savoir

- Filtre d'injection de prompt (liste de motifs) : bloque le document jusqu'à confirmation
  (`confirmer: true`). C'est un signal, pas une barrière : il ne couvre que des formulations connues.
- Juge d'injection LLM : informe, ne bloque jamais, et peut être trompé par le document qu'il lit.
  « Rien repéré » ne prouve pas qu'un document est sûr.
- Confiance des PII : celle du LLM est une auto-évaluation. Elle informe, elle ne décide jamais
  de ce qui est caviardé : toute PII détectée est caviardée.
- Mode dégradé : si le LLM est indisponible, l'API continue avec les expressions régulières seules
  (le champ `mode_degrade` le signale) ; les noms, lieux et dates de naissance peuvent alors ne pas
  être caviardés.
- Historique : si l'archivage échoue, le caviardage échoue (pas de traitement sans trace).
  Supprimer un compte conserve ses traitements (`user_id` devient vide).
- Jeton : 30 minutes, relu ni en base ni révocable ; un compte désactivé garde son accès jusqu'à
  l'expiration.
- Taille maximale d'un document : 100 000 caractères.

## 11. Problèmes fréquents

| Symptôme | Cause et remède |
|---|---|
| « Failed to load API definition » | Lancer uvicorn avec `--root-path /proxy/8000` |
| « JWT_SECRET manquante » ou « trop court » | Renseigner un secret de 32 caractères minimum dans `.env` |
| « ADMIN_PASSWORD trop court » ou « trop long » | 8 caractères minimum, 72 octets maximum |
| Erreur sur la table `users` au premier lancement | Lancer `python -m anonymia.data.init_db` |
| 500 avec `UndefinedColumn` | Relancer `python -m anonymia.data.init_db`, puis l'API |
| `KeyError: 'POSTGRES_HOST'` | `.env` absent ou incomplet, ou commande lancée hors de la racine |
| 401 alors que le mot de passe est bon | Le compte n'existe pas dans cette base, ou il est désactivé |
| Tous les verdicts du juge « unavailable » | `LLM_JUDGE_MODEL` faux (404/400), clé refusée (401/403) ou trop d'appels (429) |
| `pip install` refusé (« installé par le système ») | Activer l'environnement virtuel |

## 12. Signaler un problème

Indiquer la route et le corps envoyés, le code et la réponse reçus, le message du terminal
d'uvicorn, et avec ou sans LLM. Ne jamais coller de vrai document, de mot de passe, de clé API
ni le contenu de `.env`.

La documentation détaillée (juge, confiance, types de PII, tableau de bord, résultats mesurés)
est dans `anonymia/doc.txt`.