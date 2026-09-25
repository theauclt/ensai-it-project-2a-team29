import pytest

from ... import RegexDetector


@pytest.mark.asyncio
async def test_detect_email():
    detector = RegexDetector()

    result = await detector.detect("Mon email est test@example.com")

    assert len(result) == 1
    assert result[0].text == "test@example.com"
    assert result[0].type == "EMAIL"

