"""Shared result types used by scanner engines and reporters."""

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Ordered finding severity."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity: {value}") from exc


@dataclass(frozen=True)
class Finding:
    """A single security observation, safe to serialize in reports."""

    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line: int
    message: str
    category: str
    recommendation: str
    cve: str | None = None

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["severity"] = self.severity.name.title()
        return result
