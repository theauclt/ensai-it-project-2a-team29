from ..service.interfaces.anonymisation_strategy import AnonymisationStrategy


class PseudonymizationStrategy(AnonymisationStrategy):
    """
    Caviarde le document selon une strategie de pseudonymisation des PII détéctées
    """

