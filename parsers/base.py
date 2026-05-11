from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ValidationResult:
    """Standardized response for rule validation."""
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    normalized_content: Optional[str] = None


class BaseRuleParser(ABC):
    """
    Abstract contract for all security rule format parsers.
    Stateless and modular — no file I/O inside parsers.
    """

    @property
    @abstractmethod
    def format(self) -> str:
        """Short identifier: 'yara', 'sigma', 'suricata', etc."""

    @property
    @abstractmethod
    def extensions(self) -> List[str]:
        """Supported file extensions: ['.yar', '.yara']"""

    @abstractmethod
    def can_handle(self, chunk: str) -> bool:
        """Return True if this raw text looks like this format (auto-detect)."""

    @abstractmethod
    def split_rules(self, raw_content: str) -> List[str]:
        """Split a multi-rule string into individual raw rule strings."""

    @abstractmethod
    def validate(self, raw_rule: str) -> ValidationResult:
        """Validate syntax and semantics. Returns ValidationResult."""

    @abstractmethod
    def parse(self, raw_rule: str) -> Dict[str, Any]:
        """
        Parse raw rule into a structured dict:
        {
            "format": str,
            "identity": {"name": str, "tags": [...], "scopes": [...]},
            "metadata": {...},
            "content": str,
            "tags": [...],
            "vulnerabilities": [...],  # CVE IDs
            "references": [...],
            "sources": [...],          # authors
            "original_uuid": str | None
        }
        """

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map parsed dict to the Universal Rulezet Schema.
        Override in each parser. Default is pass-through.
        """
        return parsed_data

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} format='{self.format}'>"