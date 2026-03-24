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
    Interface for all security rule formats.
    Designed to be stateless and modular for Rulezet/RuleCast.
    """

    @property
    @abstractmethod
    def format(self) -> str:
        """Short identifier (e.g., 'yara', 'suricata')."""
        pass

    @property
    @abstractmethod
    def extensions(self) -> List[str]:
        """List of supported file extensions (e.g., ['.yar', '.yara'])."""
        pass

    @abstractmethod
    def can_handle(self, chunk: str) -> bool:
        """
        Quickly check if a text snippet or file content belongs to this format.
        Useful for 'auto-detect' when the user pastes raw text.
        """
        pass

    @abstractmethod
    def split_rules(self, raw_content: str) -> List[str]:
        """
        The 'Segmenter': Takes a multi-rule file/string and 
        returns a list of individual raw rule strings.
        """
        pass

    @abstractmethod
    def validate(self, raw_rule: str) -> ValidationResult:
        """
        Checks syntax and semantic logic. 
        Crucial before importing into Rulezet.
        """
        pass

    @abstractmethod
    def parse(self, raw_rule: str) -> Dict[str, Any]:
        """
        The 'Heavy Lifter': Transforms raw text into a structured dictionary.
        Should include: 'identity', 'metadata', 'logic', and 'tags'.
        """
        pass

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Maps format-specific keys to the Universal Rulezet Schema.
        Default implementation returns data as-is.
        """
        return parsed_data

    def __repr__(self):
        return f"<{self.__class__.__name__} format='{self.format_id}'>"