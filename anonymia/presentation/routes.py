from .routes_auth import router as auth_router
from .routes_documents import router as documents_router
from .routes_journaux import router as journaux_router

# Tous les routeurs de l'application (utilisés par main.py et par les tests)
routers = [auth_router, documents_router, journaux_router]