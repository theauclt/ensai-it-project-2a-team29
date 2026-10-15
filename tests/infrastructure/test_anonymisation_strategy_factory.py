import pytest

from anonymia.infrastructure.anonymization_strategy_factory import AnonymizationStrategyFactory
from anonymia.infrastructure.masking_strategy import MaskingStrategy
from anonymia.infrastructure.pseudonymization_strategy import PseudonymizationStrategy


def test_get_masking_strategy():
    strategy = AnonymizationStrategyFactory.get_strategy("masking")
    assert isinstance(strategy, MaskingStrategy)


def test_get_pseudonymization_strategy():
    strategy = AnonymizationStrategyFactory.get_strategy("pseudonymization")
    assert isinstance(strategy, PseudonymizationStrategy)


def test_get_unknown_strategy():
    with pytest.raises(ValueError):
        AnonymizationStrategyFactory.get_strategy("unknown")


def test_get_empty_strategy():
    with pytest.raises(ValueError):
        AnonymizationStrategyFactory.get_strategy("")