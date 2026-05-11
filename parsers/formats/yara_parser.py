import re
import yara
import plyara
import plyara.utils
from typing import Dict, Any, List
from parsers.base import BaseRuleParser, ValidationResult


def insert_import_module(rule_text, module_name):
    lines = rule_text.strip().splitlines()
    if not any(line.strip().startswith(f'import "{module_name}"') for line in lines):
        return f'import "{module_name}"\n' + rule_text
    return rule_text


class YaraParser(BaseRuleParser):
    """
    Robust YARA Parser using regex-based splitting to isolate rules.
    Resilient to mixed valid/invalid rules in large files.
    """

    YARA_MODULES = {"pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho", "vt"}

    # Matches rule headers including:
    # - optional global / private modifiers (any order, any combination)
    # - rule name
    # - optional tag list ": tag1 tag2 ..."  (one OR multiple tags)
    # - opening brace
    SPLIT_PATTERN = re.compile(
        r'(?:global\s+|private\s+)*rule\s+[\w\d_]+\s*(?::\s*(?:[\w\d_]+\s*)+)?\{'
    )

    def __init__(self):
        self.ply = plyara.Plyara()

    @property
    def format(self) -> str:
        return "yara"

    @property
    def extensions(self) -> List[str]:
        return [".yar", ".yara"]

    def can_handle(self, chunk: str) -> bool:
        return bool(self.SPLIT_PATTERN.search(chunk))

    def validate(self, content: str, **kwargs) -> ValidationResult:
        externals = {}
        attempts = 0
        max_attempts = 10
        current_rule_text = content

        while attempts < max_attempts:
            try:
                yara.compile(source=current_rule_text, externals=externals)
                return ValidationResult(ok=True, errors=[], normalized_content=current_rule_text)
            except yara.SyntaxError as e:
                error_msg = str(e)
                match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
                if match_id:
                    var_name = match_id.group(1)
                    if var_name in self.YARA_MODULES:
                        current_rule_text = insert_import_module(current_rule_text, var_name)
                        attempts += 1
                        continue
                    else:
                        externals[var_name] = "dummy"
                        attempts += 1
                        continue
                return ValidationResult(ok=False, errors=[error_msg], normalized_content=current_rule_text)
            except Exception as e:
                return ValidationResult(ok=False, errors=[str(e)], normalized_content=current_rule_text)

        return ValidationResult(ok=False, errors=["Max validation attempts exceeded"], normalized_content=current_rule_text)

    def split_rules(self, raw_content: str) -> List[str]:
        """
        Regex-based splitting — finds each rule header and slices content between them.

        Fixed vs original:
        - Handles multiple tags: "rule Foo : tag1 tag2 tag3 {"
        - Handles modifiers in any order: "global private rule Foo {"
        - Original pattern only matched a single tag and missed multi-tag rules
        """
        matches = list(self.SPLIT_PATTERN.finditer(raw_content))

        rules = []
        for i, match in enumerate(matches):
            start = match.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(raw_content)
            rule_chunk = raw_content[start:end].strip()
            if rule_chunk:
                rules.append(rule_chunk)

        return rules

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        self.ply.clear()
        try:
            parsed_list = self.ply.parse_string(raw_rule)
            if not parsed_list:
                raise ValueError("Plyara failed to produce AST for this block")

            data = parsed_list[0]
            meta = {m['name']: m['value'] for m in data.get('metadata', [])}
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', meta.get("description", ""), re.IGNORECASE)

            return {
                "format": self.format,
                "identity": {
                    "name": data.get('rule_name'),
                    "tags": data.get('tags', []),
                    "scopes": data.get('scopes', []),
                },
                "metadata": meta,
                "content": raw_rule,
                "tags": data.get('tags', []),
                "vulnerabilities": cves,
                "references": [meta.get('reference')] if meta.get('reference') else [],
                "sources": [meta.get('author')] if meta.get('author') else [],
                "original_uuid": meta.get("id") or meta.get("uuid"),
                "status": "parsed",
            }
        except Exception as e:
            name_match = re.search(r'rule\s+(\w+)', raw_rule)
            return {
                "format": self.format,
                "identity": {"name": name_match.group(1) if name_match else "unknown", "tags": [], "scopes": []},
                "metadata": {},
                "content": raw_rule,
                "tags": [],
                "vulnerabilities": [],
                "references": [],
                "sources": [],
                "original_uuid": None,
                "status": "parsing_error",
                "error": str(e),
            }

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map to the Universal Rulezet Schema."""
        sources = parsed_data.get("sources", [])
        return {
            "title": parsed_data.get("identity", {}).get("name"),
            "format": self.format,
            "description": parsed_data.get("metadata", {}).get("description", ""),
            "author": sources[0] if sources else "Unknown",
            "content": parsed_data.get("content", ""),
            "tags": parsed_data.get("tags", []),
            "original_uuid": parsed_data.get("original_uuid"),
        }