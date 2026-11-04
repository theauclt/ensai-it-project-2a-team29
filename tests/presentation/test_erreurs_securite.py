import pytest

from anonymia.presentation import security
from anonymia.presentation.routes_admin import _erreur_http
from anonymia.service.business_objects.user import User


def test_sans_jwt_secret_la_creation_de_jeton_echoue(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        security.create_token(User(1, "alice", "h", "USER"))


def test_une_erreur_inattendue_n_est_pas_transformee_en_reponse_http():
    # Seules les erreurs métier connues deviennent des codes HTTP ; le reste remonte (500)
    with pytest.raises(ZeroDivisionError):
        _erreur_http(ZeroDivisionError())