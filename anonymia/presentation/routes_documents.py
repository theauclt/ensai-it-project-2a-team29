from fastapi import APIRouter, Depends, HTTPException, status

from ..service.business_objects.user import User
from ..service.detection_service import DetectionService
from .providers import get_detection_service
from .schemas import (
    AnalyseResponse,
    CaviardageResponse,
    CaviarderRequest,
    DocumentRequest,
    PIIResponse,
    StrategiesResponse,
)
from .security import get_current_user

router = APIRouter(prefix="/documents", tags=["Documents"])


@router.post("/analyser", response_model=AnalyseResponse)
async def analyser(
    body: DocumentRequest,
    _user: User = Depends(get_current_user),
    service: DetectionService = Depends(get_detection_service),
) -> AnalyseResponse:
    """Renvoie la liste fusionnée des PII détectées (regex et LLM en parallèle)."""
    spans = await service.analyze(body.contenu)
    return AnalyseResponse(
        pii=[
            PIIResponse(
                texte=s.text, type=s.type, debut=s.start, fin=s.end, detecteur=s.source_detector
            )
            for s in spans
        ]
    )


@router.post("/caviarder", response_model=CaviardageResponse)
async def caviarder(
    body: CaviarderRequest,
    user: User = Depends(get_current_user),
    service: DetectionService = Depends(get_detection_service),
) -> CaviardageResponse:
    """Renvoie le document caviardé et archive les métadonnées du traitement."""
    if body.strategie not in service.available_strategies():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Stratégie inconnue. Disponibles : {', '.join(service.available_strategies())}",
        )
    document = await service.detect(body.contenu, body.strategie, user.id)
    return CaviardageResponse(document_caviarde=document)


@router.get("/strategies", response_model=StrategiesResponse)
async def strategies(
    _user: User = Depends(get_current_user),
    service: DetectionService = Depends(get_detection_service),
) -> StrategiesResponse:
    """Liste les stratégies d'anonymisation disponibles."""
    return StrategiesResponse(strategies=service.available_strategies())