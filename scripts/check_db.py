"""
Vérifie à la main que les dépôts PostgreSQL et l'authentification fonctionnent.

Usage (après init_db et create_user) :
    python -m scripts.check_db <login> <mot_de_passe>
"""
import asyncio
import sys
from datetime import UTC, datetime

from dotenv import load_dotenv

load_dotenv()

from anonymia.persistence.postgres_archive_repository import PostgresArchiveRepository
from anonymia.persistence.postgres_user_repository import PostgresUserRepository
from anonymia.service.authentification_service import AuthentificationService
from anonymia.service.business_objects.audit_entry import AuditEntry


async def main(login: str, password: str) -> int:
    auth = AuthentificationService(PostgresUserRepository())

    print("1. Mauvais mot de passe refusé :", await auth.authentifier(login, "mauvais") is None)
    user = await auth.authentifier(login, password)
    print("2. Bon mot de passe accepté    :", user is not None)
    if user is None:
        return 1

    archive = PostgresArchiveRepository()
    await archive.save(AuditEntry(
        user_id=user.id,
        date_traitement=datetime.now(UTC),
        hash_document="0" * 64,
        strategie_anonymisation="masking",
        detecteurs_contributeurs="RegexDetector",
        nb_pii_detectees=3,
    ))
    mine = await archive.find_by_user(user.id)
    print(f"3. Traitement enregistré       : {len(mine) >= 1} ({len(mine)} pour cet utilisateur)")
    print(f"4. find_all                    : {len(await archive.find_all())} traitement(s) au total")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage : python -m scripts.check_db <login> <mot_de_passe>")
        sys.exit(1)
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))