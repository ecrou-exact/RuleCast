import argparse
import sys
import json
import os
from typing import List


from parsers.base import BaseRuleParser
from parsers.formats.yara_parser import YaraParser
# Prochainement : from parsers.formats.suricata_parser import SuricataParser

class RuleCastEngine:
    def __init__(self):
        # Enregistre tes parsers ici
        self.parsers: List[BaseRuleParser] = [
            YaraParser(),
            # Ajoute les nouveaux ici au fur et à mesure
        ]

    def execute(self, content: str):
        results = []

        selected_parser = None
        for p in self.parsers:
            if p.can_handle(content):
                selected_parser = p
                break

        if selected_parser:
            print(f"[*] Detected format: {selected_parser.format}") # Utilise format_id

        
        if not selected_parser:
            print(f"[-] Error: No compatible parser found for this content.", file=sys.stderr)
            return

        print(f"[*] Detected format: {selected_parser.format}", file=sys.stderr)

        # 1. Découpage en règles individuelles
        raw_rules = selected_parser.split_rules(content)
        print(f"[*] Found {len(raw_rules)} rule(s).", file=sys.stderr)

        for raw in raw_rules:
            # 2. Validation
            validation = selected_parser.validate(raw)
            
            # 3. Parsing
            data = selected_parser.parse(raw)
            
            # On enrichit avec le status de validation
            data["validation"] = {
                "ok": validation.ok if hasattr(validation, 'ok') else validation.get('is_valid'),
                "errors": validation.errors if hasattr(validation, 'errors') else validation.get('errors')
            }
            
            results.append(data)

        # Sortie finale en JSON propre
        print(json.dumps(results, indent=4))

def main():
    parser = argparse.ArgumentParser(description="RuleCast: Security Rule Parser & Normalizer")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to a rule file")
    group.add_argument("-t", "--text", help="Raw rule text (copy-paste)")

    args = parser.parse_args()

    content = ""
    if args.file:
        if not os.path.exists(args.file):
            print(f"[-] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        content = args.text

    engine = RuleCastEngine()
    engine.execute(content)

if __name__ == "__main__":
    main()