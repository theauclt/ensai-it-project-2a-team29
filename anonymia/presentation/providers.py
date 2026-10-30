"""
Fournisseurs de services pour les routes (Depends).

Les services sont construits une seule fois au démarrage (voir main.py) et
rangés dans app.state. Les tests les remplacent avec dependency_overrides.
"""
from fastapi import Request

from ..service.authentification_service import AuthentificationService
from ..service.detection_service import DetectionService
from ..service.history_service import HistoryService


def get_detection_service(request: Request) -> DetectionService:
    return request.app.state.detection_service


def get_history_service(request: Request) -> HistoryService:
    return request.app.state.history_service


def get_auth_service(request: Request) -> AuthentificationService:
    return request.app.state.auth_service