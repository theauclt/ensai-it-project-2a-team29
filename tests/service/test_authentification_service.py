from unittest.mock import AsyncMock

import bcrypt
import pytest

from anonymia.service.authentification_service import AuthentificationService
from anonymia.service.business_objects.user import User


@pytest.fixture
def user_repository():
    return AsyncMock()


@pytest.fixture
def authentification_service(user_repository):
    return AuthentificationService(user_repository)


@pytest.fixture
def user():
    password = "motdepasse123"
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")

    return User(
        id="123",
        login="test_user",
        password_hash=password_hash,
        role="utilisateur",
        est_active=True,
    )


@pytest.mark.asyncio
async def test_authentification_reussie(
    user_repository,
    authentification_service,
    user,
):
    # GIVEN
    user_repository.find_by_login.return_value = user

    # WHEN
    result = await authentification_service.authentifier(
        "test_user",
        "motdepasse123",
    )

    # THEN
    assert result is user
    user_repository.find_by_login.assert_awaited_once_with("test_user")


@pytest.mark.asyncio
async def test_authentification_utilisateur_inexistant(
    user_repository,
    authentification_service,
):
    # GIVEN
    user_repository.find_by_login.return_value = None

    # WHEN
    result = await authentification_service.authentifier(
        "inexistant",
        "motdepasse123",
    )

    # THEN
    assert result is None
    user_repository.find_by_login.assert_awaited_once_with("inexistant")


@pytest.mark.asyncio
async def test_authentification_mauvais_mot_de_passe(
    user_repository,
    authentification_service,
    user,
):
    # GIVEN
    user_repository.find_by_login.return_value = user

    # WHEN
    result = await authentification_service.authentifier(
        "test_user",
        "mauvais_mot_de_passe",
    )

    # THEN
    assert result is None


@pytest.mark.asyncio
async def test_authentification_compte_desactive(
    user_repository,
    authentification_service,
    user,
):
    # GIVEN
    user.est_active = False
    user_repository.find_by_login.return_value = user

    # WHEN
    result = await authentification_service.authentifier(
        "test_user",
        "motdepasse123",
    )

    # THEN
    assert result is None