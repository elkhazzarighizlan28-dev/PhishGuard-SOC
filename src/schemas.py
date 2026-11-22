
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True, slots=True)
class Finding:
    """Validated security finding produced by PhishGuard."""

    VALID_SEVERITIES: ClassVar[frozenset[str]] = frozenset({
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    })

    type: str
    severity: str
    description: str
    evidence: str
    score: int

    def __post_init__(self) -> None:
        if not isinstance(self.type, str) or not self.type.strip():
            raise ValueError("Finding type must be a non-empty string.")

        if not isinstance(self.severity, str):
            raise TypeError("Severity must be a string.")

        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity!r}")

        if not isinstance(self.description, str):
            raise TypeError("Description must be a string.")

        if not isinstance(self.evidence, str):
            raise TypeError("Evidence must be a string.")

        if type(self.score) is not int:
            raise TypeError("Score must be an integer.")

        if not 0 <= self.score <= 100:
            raise ValueError("Score must be between 0 and 100.")

    def to_dict(self) -> dict[str, str | int]:
        """Convert the model to the legacy dictionary format."""
        return {
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "score": self.score,
        }
