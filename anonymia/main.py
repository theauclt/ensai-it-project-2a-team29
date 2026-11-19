"""
Point d'entrée de l'API.

Lancement (depuis la racine du dépôt) :
    uvicorn anonymia.main:app --reload
La documentation interactive est ensuite sur http://localhost:8000/docs
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from .dependencies import (
    build_admin_service,
    build_archive_repository,
    build_auth_service,
    build_detection_service,
    build_history_service,
    build_pool,
    build_surveillance_injections,
    build_tentative_injection_repository,
    build_user_repository,
)
from .presentation.routes import routers
from .presentation.security import verifier_secret


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Échec immédiat au démarrage plutôt qu'à la première connexion
    verifier_secret()

    # Pool PostgreSQL : on attend une première connexion pour échouer tout de suite si la base est injoignable
    pool = build_pool()
    await pool.open(wait=True)

    archive_repo = build_archive_repository(pool)
    user_repo = build_user_repository(pool)
    # Tentatives d'injection par compte : signalement à 3, désactivation automatique à 10
    surveillance = build_surveillance_injections(build_tentative_injection_repository(pool), user_repo)
    # LLM_ENABLED=false : démarrage avec les expressions régulières seules
    with_llm = os.environ.get("LLM_ENABLED", "true").lower() != "false"
    with_ner = os.environ.get("NER_ENABLED", "false").lower() == "true"

    app.state.detection_service = build_detection_service(
        archive_repo, with_llm=with_llm, with_ner=with_ner, surveillance=surveillance
    )
    app.state.history_service = build_history_service(archive_repo, user_repo)
    app.state.auth_service = build_auth_service(user_repo)
    app.state.admin_service = build_admin_service(user_repo, surveillance=surveillance)

    # F1 : compte administrateur initial, créé une seule fois (sans effet s'il existe)
    admin_login = os.environ.get("ADMIN_LOGIN")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if admin_login and admin_password:
        await app.state.auth_service.creer_admin_initial(admin_login, admin_password)

    yield

    await app.state.detection_service.aclose()  # ferme le client HTTP du LLM
    await pool.close()


app = FastAPI(
    title="Anonymia",
    description="Détection et caviardage de données personnelles",
    lifespan=lifespan,
)

for router in routers:
    app.include_router(router)


@app.get("/", include_in_schema=False)
async def accueil():
    return RedirectResponse("/docs")