import os
import re
import yara
import plyara
import plyara.utils
from typing import Dict, Any, List, Optional
from parsers.base import BaseRuleParser, ValidationResult

# Helper function from your snippet
def insert_import_module(rule_text, module_name):
    lines = rule_text.strip().splitlines()
    if not any(line.strip().startswith(f'import "{module_name}"') for line in lines):
        return f'import "{module_name}"\n' + rule_text
    return rule_text

class YaraParser(BaseRuleParser):
    """
    Advanced YARA Parser integrating plyara for AST extraction 
    and yara-python for dynamic compilation validation.
    """

    YARA_MODULES = {"pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho", "vt"}

    def __init__(self):
        self.ply = plyara.Plyara()

    @property
    def format(self) -> str:
        return "yara"

    @property
    def extensions(self) -> List[str]:
        return [".yar", ".yara"]

    def can_handle(self, chunk: str) -> bool:
        """Fast check for YARA signatures."""
        pattern = r'(?:global\s+|private\s+)?rule\s+[\w\d_]+\s*(?::\s*[\w\d_]+\s*)?\{'
        return bool(re.search(pattern, chunk))

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validates the YARA rule by attempting compilation.
        Auto-fixes missing imports for standard modules.
        """
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
                # Check for undefined identifiers (like missing 'import "pe"')
                match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
                if match_id:
                    var_name = match_id.group(1)
                    if var_name in self.YARA_MODULES:
                        current_rule_text = insert_import_module(current_rule_text, var_name)
                        attempts += 1
                        continue
                    else:
                        # If it's not a module, treat as external variable
                        externals[var_name] = "dummy"
                        attempts += 1
                        continue
                return ValidationResult(ok=False, errors=[error_msg], normalized_content=current_rule_text)
            except Exception as e:
                return ValidationResult(ok=False, errors=[str(e)], normalized_content=current_rule_text)

        return ValidationResult(ok=False, errors=["Max validation attempts exceeded"], normalized_content=current_rule_text)

    def split_rules(self, raw_content: str) -> List[str]:
        """
        Robust YARA splitter that handles comments, strings, and nested braces.
        """
        rules = []
        brace_level = 0
        inside_string = False
        inside_regex = False
        string_char = None
        inside_line_comment = False
        inside_block_comment = False
        current_rule = []
        in_rule = False
        escaped = False

        content = raw_content
        i = 0
        while i < len(content):
            char = content[i]
            nxt = content[i + 1] if i + 1 < len(content) else ""

            # Handle strings/regex (skip logic)
            if inside_string or inside_regex:
                current_rule.append(char)
                if not escaped and char == (string_char if inside_string else "/"):
                    inside_string = False
                    inside_regex = False
                escaped = (char == "\\" and not escaped)
                i += 1; continue

            # Handle comments
            if not inside_line_comment and not inside_block_comment:
                if char == "/" and nxt == "/":
                    inside_line_comment = True; i += 2; continue
                if char == "/" and nxt == "*":
                    inside_block_comment = True; i += 2; continue

            if inside_line_comment:
                if char == "\n": inside_line_comment = False
                i += 1; continue
            if inside_block_comment:
                if char == "*" and nxt == "/":
                    inside_block_comment = False; i += 2
                else: i += 1
                continue

            # Detect Start of string/regex
            if char in ('"', "'"):
                inside_string = True; string_char = char; escaped = False
            elif char == "/" and nxt not in ("/", "*"):
                inside_regex = True; escaped = False

            # Rule detection logic
            if not in_rule and content[i:i+4] == "rule":
                # Lookahead to confirm it's a rule definition
                if re.match(r'rule\s+[\w\d_]+', content[i:]):
                    in_rule = True
                    current_rule = []

            if char == "{": brace_level += 1
            elif char == "}": brace_level -= 1

            if in_rule:
                current_rule.append(char)
                if brace_level == 0 and char == "}":
                    rules.append("".join(current_rule).strip())
                    in_rule = False
            i += 1
        return rules

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        """
        Deep parsing using plyara to extract structured metadata and logic.
        """
        self.ply.clear()
        try:
            # Using plyara to get the AST
            parsed_list = self.ply.parse_string(raw_rule)
            if not parsed_list:
                raise ValueError("Plyara failed to produce AST")
            
            data = parsed_list[0]
            # Convert plyara metadata list to dict
            meta = {m['name']: m['value'] for m in data.get('metadata', [])}
            
            # Simple CVE detection (placeholder for your detect_cve utility)
            description = meta.get("description", "")
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', description, re.IGNORECASE)

            return {
                "format": self.format,
                "identity": {
                    "name": data.get('rule_name'),
                    "tags": data.get('tags', []),
                    "scopes": data.get('scopes', [])
                },
                "metadata": meta,
                "content": raw_rule,
                "tags": data.get('tags', []),
                "vulnerabilities": cves,
                "references": [meta.get('reference')] if meta.get('reference') else [],
                "sources": [meta.get('author')] if meta.get('author') else [],
                "original_uuid": meta.get("id") or meta.get("uuid")
            }
        except Exception as e:
            # Fallback to Regex if plyara fails
            name_match = re.search(r'rule\s+(\w+)', raw_rule)
            return {
                "format": self.format,
                "identity": {"name": name_match.group(1) if name_match else "unknown"},
                "metadata": {},
                "content": raw_rule,
                "error": str(e)
            }

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Standardizes the output for Rulezet-core."""
        return {
            "title": parsed_data['identity'].get('name'),
            "format": self.format,
            "description": parsed_data['metadata'].get('description', ''),
            "author": parsed_data['sources'][0] if parsed_data['sources'] else 'Unknown',
            "content": parsed_data['content'],
            "tags": parsed_data['tags'],
            "original_uuid": parsed_data['original_uuid']
        }