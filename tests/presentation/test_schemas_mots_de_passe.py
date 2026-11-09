"""Un mot de passe est limité en octets (bcrypt), pas en caractères."""
import pytest
from pydantic import ValidationError

from anonymia.presentation.schemas import CreerUtilisateurRequest, LoginRequest

LIMITE = 72


def test_72_octets_sont_acceptes():
    assert LoginRequest(login="a", mot_de_passe="a" * LIMITE).mot_de_passe
    assert CreerUtilisateurRequest(login="a", mot_de_passe="a" * LIMITE, role="USER")


def test_73_octets_sont_refuses_a_la_connexion():
    with pytest.raises(ValidationError, match="trop long"):
        LoginRequest(login="a", mot_de_passe="a" * (LIMITE + 1))


def test_les_caracteres_accentues_comptent_pour_deux_octets():
    # 40 caractères mais 80 octets : max_length=128 caractères ne suffit pas
    with pytest.raises(ValidationError, match="trop long"):
        CreerUtilisateurRequest(login="a", mot_de_passe="é" * 40, role="USER")


def test_la_creation_de_compte_garde_sa_limite_de_caracteres():
    with pytest.raises(ValidationError):
        CreerUtilisateurRequest(login="a", mot_de_passe="", role="USER")