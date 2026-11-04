from fastapi import APIRouter, Depends, HTTPException, status

from ..service.business_objects.injection_verdict import metadonnees_juge
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
    VerdictJugeResponse,
)
from .security import get_current_user

router = APIRouter(prefix="/documents", tags=["Documents"])

# Sans réponse du LLM, seules les règles (regex) ont tourné : c'est le mode dégradé
DETECTEUR_LLM = "LLMDetector"


@router.post("/analyser", response_model=AnalyseResponse)
async def analyser(
    body: DocumentRequest,
    _user: User = Depends(get_current_user),
    service: DetectionService = Depends(get_detection_service),
) -> AnalyseResponse:
    """Renvoie la liste fusionnée des PII détectées (regex et LLM en parallèle)."""
    spans, detecteurs = await service.analyze_with_status(body.contenu)
    return AnalyseResponse(
        detecteurs=detecteurs,
        mode_degrade=DETECTEUR_LLM not in detecteurs,
        types_injection=service.injection_types(body.contenu),
        pii=[
            PIIResponse(
                texte=s.text,
                type=s.type,
                debut=s.start,
                fin=s.end,
                detecteur=s.source_detector,
                confiance=s.confidence,
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
    resultat = await service.detect(body.contenu, body.strategie, user.id, body.confirmer)
    if resultat.confirmation_requise:
        return CaviardageResponse(
            confirmation_requise=True,
            types_injection=resultat.types_injection,
            avertissements=[
                (
                    "Ce document contient des motifs ressemblant à une injection de prompt. "
                    "Il n'a pas été traité. Pour le traiter quand même, renvoyez la même "
                    'requête avec "confirmer": true (relecture humaine indispensable).'
                )
            ],
        )
    avertissements = []
    if resultat.types_injection:
        avertissements.append("Injection de prompt suspectée : relisez attentivement le résultat.")
    statut_juge, type_juge = metadonnees_juge(resultat.verdict_juge)
    if statut_juge == "detected":
        avertissements.append(
            "Le juge LLM a repéré une tentative de manipulation du système : relisez attentivement le résultat."
        )
    return CaviardageResponse(
        document_caviarde=resultat.document,
        avertissements=avertissements,
        detecteurs=resultat.detecteurs,
        mode_degrade=DETECTEUR_LLM not in resultat.detecteurs,
        types_injection=resultat.types_injection,
        juge=VerdictJugeResponse(statut=statut_juge, type=type_juge) if statut_juge else None,
    )


@router.get("/strategies", response_model=StrategiesResponse)
async def strategies(
    _user: User = Depends(get_current_user),
    service: DetectionService = Depends(get_detection_service),
) -> StrategiesResponse:
    """Liste les stratégies d'anonymisation disponibles."""
    return StrategiesResponse(strategies=service.available_strategies())