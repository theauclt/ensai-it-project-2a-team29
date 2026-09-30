from ..infrastructure.masking_strategy import MaskingStrategy
from ..infrastructure.pseudonymization_strategy import PseudonymizationStrategy
from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy


class AnonymizationStrategyFactory:

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