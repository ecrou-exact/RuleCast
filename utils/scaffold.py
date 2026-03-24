import os
import sys

def create_parser_template(format_name: str):
    # Normalize the format name (lowercase, no spaces)
    format_name = format_name.lower().strip().replace(" ", "_")
    
    # Calculate paths relative to this script's location
    # project/utils/scaffold.py -> target is project/parsers/formats/
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(base_dir, "parsers", "formats")
    
    filename = f"{format_name}_parser.py"
    filepath = os.path.join(target_dir, filename)

    # --- CRITICAL CHECK: Does it already exist? ---
    if os.path.exists(filepath):
        print(f"[-] ERROR: A parser for '{format_name}' already exists at:")
        print(f"    {filepath}")
        print("[-] Aborting to prevent accidental overwrite.")
        return

    # Ensure directories exist
    os.makedirs(target_dir, exist_ok=True)
    
    # Create __init__.py files for proper Python packaging
    for folder in [os.path.join(base_dir, "parsers"), target_dir]:
        init_path = os.path.join(folder, "__init__.py")
        if not os.path.exists(init_path):
            with open(init_path, 'w') as f: pass

    # Template generation
    class_name = format_name.capitalize()
    template = f"""from typing import Dict, Any, List, Optional
from parsers.base import BaseRuleParser

class {class_name}Parser(BaseRuleParser):
    \"\"\"
    Auto-generated parser for {format_name.upper()} format.
    \"\"\"

    @property
    def format(self) -> str:
        \"\"\"Unique identifier for the format (e.g., 'yara').\"\"\"
        return "{format_name}"

    @property
    def extention(self) -> str:
        \"\"\"File extension for the format (e.g., '.yar').\"\"\"
        # TODO: Return the correct extension string
        return ".{format_name}"

    def can_handle(self, chunk: str) -> bool:
        \"\"\"
        TODO: Implement fast check logic for {format_name.upper()}.
        \"\"\"
        raise NotImplementedError("Implement can_handle() for {format_name}")

    def split_rules(self, raw_content: str) -> List[str]:
        \"\"\"
        TODO: Implement logic to split a multi-rule file into individual {format_name.upper()} strings.
        \"\"\"
        return [raw_content]

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        \"\"\"
        TODO: Extract identifiers, metadata, logic, and tags from the raw string.
        \"\"\"
        return {{
            "format": self.format,
            "identity": {{}},
            "metadata": {{}},
            "content": raw_rule,
            "tags": [],
            "vulnerabilities": [],
            "references": [],
            "sources": [],
            "original_uuid": None
        }}

    def validate(self, raw_rule: str) -> Dict[str, Any]:
        \"\"\"
        TODO: Implement syntax and semantic validation for {format_name.upper()}.
        \"\"\"
        return {{
            "is_valid": True, 
            "errors": [], 
            "warnings": []
        }}

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        \"\"\"
        Maps {format_name.upper()} specific keys to the Universal Rulezet Schema.
        \"\"\"
        return super().normalize(parsed_data)
"""

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(template)
        print(f"[+] SUCCESS: Created {filepath}")
        print(f"[!] Template matches your BaseRuleParser contract.")
        print(f"[!] Ready for logic implementation in {class_name}Parser.")
    except Exception as e:
        print(f"[-] FAILED to write file: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m utils.scaffold <format_name>")
    else:
        create_parser_template(sys.argv[1])