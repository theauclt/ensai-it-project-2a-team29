"""Contrôle du secret JWT au démarrage (audit ER3-03)."""
import pytest

from anonymia.presentation.security import SECRET_MIN_CARACTERES, verifier_secret


def test_secret_absent_refuse(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        verifier_secret()


def test_secret_trop_court_refuse(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * (SECRET_MIN_CARACTERES - 1))

    with pytest.raises(RuntimeError, match="trop court"):
        verifier_secret()


def test_secret_assez_long_accepte(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * SECRET_MIN_CARACTERES)

    assert verifier_secret() is None