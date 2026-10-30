from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy
from .masking_strategy import MaskingStrategy
from .pseudonymization_strategy import PseudonymizationStrategy


class AnonymizationStrategyFactory:
    STRATEGIES = ("masking", "pseudonymization")

    @classmethod
    def available_strategies(cls) -> list[str]:
        """Noms des stratégies que get_strategy sait construire."""
        return list(cls.STRATEGIES)

    @classmethod
    def get_strategy(cls, strategy: str) -> AnonymisationStrategy:
        """
        blbla
        """
        if strategy == "masking":
            return MaskingStrategy()

        if strategy == "pseudonymization":
            return PseudonymizationStrategy()

        raise ValueError(f"Stratégie d'anonymisation non supportée: {strategy}")