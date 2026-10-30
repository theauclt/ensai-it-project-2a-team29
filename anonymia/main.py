"""
Point d'entrée de l'API.

Lancement (depuis la racine du dépôt) :
    uvicorn anonymia.main:app --reload
La documentation interactive est ensuite sur http://localhost:8000/docs
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .dependencies import (
    build_archive_repository,
    build_auth_service,
    build_detection_service,
    build_history_service,
    build_user_repository,
)
from .presentation.routes import routers


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Échec immédiat au démarrage plutôt qu'à la première connexion
    if not os.environ.get("JWT_SECRET"):
        raise RuntimeError("Variable d'environnement manquante : JWT_SECRET")

    archive_repo = build_archive_repository()
    user_repo = build_user_repository()
    # LLM_ENABLED=false : démarrage avec les expressions régulières seules
    with_llm = os.environ.get("LLM_ENABLED", "true").lower() != "false"

    app.state.detection_service = build_detection_service(archive_repo, with_llm=with_llm)
    app.state.history_service = build_history_service(archive_repo, user_repo)
    app.state.auth_service = build_auth_service(user_repo)

    yield

    await app.state.detection_service.aclose()  # ferme le client HTTP du LLM


app = FastAPI(
    title="Anonymia",
    description="Détection et caviardage de données personnelles",
    lifespan=lifespan,
)

for router in routers:
    app.include_router(router)

from fastapi.responses import RedirectResponse


@app.get("/", include_in_schema=False)
async def accueil():
    return RedirectResponse("/docs")