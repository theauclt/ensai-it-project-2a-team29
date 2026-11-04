from dataclasses import dataclass, field


@dataclass
class AnonymizationResult:
    document: str | None
    types_injection: list[str] = field(default_factory=list)
    confirmation_requise: bool = False