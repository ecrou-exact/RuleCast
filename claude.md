# RuleCast — Project Reference for Claude

> This file is the source of truth for all future work on RuleCast.
> Read this before writing any code. Never invent paths, imports, or structure — check here first.

---

## 1. What is RuleCast?

**RuleCast** (`rulezet-cast`) is a standalone Python CLI tool and future library that parses, validates, and normalizes cybersecurity detection rules from multiple formats (YARA, Sigma, Suricata, etc.) into structured JSON.

**End goal:** become a library or git submodule consumed by [rulezet-core](https://github.com/ngsoti/rulezet-core), replacing its current `app/features/rule/rule_format/` layer which has duplicated logic, mixes I/O with parsing, and is hard to maintain.

**Current state:** YARA parser is the only fully implemented format. Architecture is stable. Work ahead is implementing the remaining parsers and packaging the lib.

**Repo:** https://github.com/rulezet/rulezet-cast.git

---

## 2. Exact File Structure

```
rulezet-cast/
├── main.py                          # CLI — interactive menu + direct commands
├── requirements.txt                 # plyara==2.2.8, yara-python==4.5.4
├── claude.md                        # this file
├── parsers/
│   ├── __init__.py                  # ALL_PARSERS list — register parsers here
│   ├── base.py                      # BaseRuleParser (ABC) + ValidationResult
│   ├── engine.py                    # RuleCastEngine + ParseResult
│   └── formats/
│       └── yara_parser.py           # YARA — only implemented format so far
├── utils/
│   └── scaffold.py                  # generates a new parser template file
├── tests/
│   └── yara.yar                     # YARA test fixture
└── doc/
    └── logo.png
```

**Import paths — always use these, never invent others:**

```python
from parsers.base import BaseRuleParser, ValidationResult
from parsers.engine import RuleCastEngine, ParseResult
from parsers import ALL_PARSERS
from parsers.formats.yara_parser import YaraParser
from utils.scaffold import create_parser_template
```

---

## 3. Core Data Structures

### `ValidationResult` — `parsers/base.py`

```python
@dataclass
class ValidationResult:
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    normalized_content: Optional[str] = None
```

Returned by every `validate()` call. Same shape for every format.

### `ParseResult` — `parsers/engine.py`

```python
class ParseResult:
    raw: str                    # original raw rule string
    validation: ValidationResult
    parsed: Dict[str, Any]      # output of parser.parse()
    normalized: Dict[str, Any]  # output of parser.normalize()
    format_name: str

    def to_dict(self) -> Dict[str, Any]: ...
```

Produced by the engine for each rule processed. `to_dict()` is used for `--json` output.

---

## 4. The Contract — `BaseRuleParser` (`parsers/base.py`)

Every format parser inherits from this and implements all abstract methods.

```python
class BaseRuleParser(ABC):

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
        """Split a multi-rule string into individual raw rule strings. No file I/O here."""

    @abstractmethod
    def validate(self, raw_rule: str) -> ValidationResult:
        """Check syntax and semantics. Returns ValidationResult."""

    @abstractmethod
    def parse(self, raw_rule: str) -> Dict[str, Any]:
        """Extract structured data from the rule. Returns the parse() schema (see below)."""

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map parse() output to the Rulezet schema. Override per parser. Default: pass-through."""
        return parsed_data
```

### `parse()` output schema — mandatory for every format

```python
{
    "format": str,
    "identity": {
        "name": str,            # rule name / title
        "tags": List[str],
        "scopes": List[str],    # e.g. ["global", "private"] for YARA
    },
    "metadata": Dict[str, Any],    # raw key=value pairs from the rule's meta block
    "content": str,                # original raw rule string, preserved exactly
    "tags": List[str],
    "vulnerabilities": List[str],  # CVE IDs detected (e.g. ["CVE-2021-44228"])
    "references": List[str],
    "sources": List[str],          # authors
    "original_uuid": Optional[str],
}
```

**Critical rule:** both the normal parse path AND the fallback (on exception) must return ALL keys with safe defaults. A partial dict will crash `normalize()`.

### `normalize()` output schema — Rulezet-core compatible

```python
{
    "title": str,
    "format": str,
    "description": str,
    "author": str,
    "content": str,              # = "to_string" in rulezet-core
    "tags": List[str],
    "original_uuid": Optional[str],
}
```

**Always use `.get()` with defaults in `normalize()`** — never direct key access like `parsed_data['sources']`. The parsed dict may come from the fallback path.

---

## 5. The Engine — `parsers/engine.py`

Parsers are registered **explicitly** in `parsers/__init__.py`. No magic autodiscovery.

### Public API

```python
class RuleCastEngine:
    def __init__(self, parsers: Optional[List[BaseRuleParser]] = None):
        self.parsers = parsers if parsers is not None else ALL_PARSERS

    def detect_format(self, content: str) -> Optional[BaseRuleParser]:
        """First parser whose can_handle() returns True, or None."""

    def get_parser(self, format_name: str) -> Optional[BaseRuleParser]:
        """Parser by exact format name (case-insensitive), or None."""

    def process(self, content: str, format_name: Optional[str] = None) -> List[ParseResult]:
        """Full pipeline on a string. Raises ValueError if format unknown/undetectable."""

    def process_file(self, filepath: str, format_name: Optional[str] = None) -> List[ParseResult]:
        """Reads file, calls process(). Only place file I/O happens in the engine."""

    def list_parsers(self) -> List[Dict[str, Any]]:
        """Returns [{format, extensions, class}, ...] for all registered parsers."""
```

### Pipeline inside `process()`

```
detect_format() or get_parser()
    → split_rules(content)           # list of raw rule strings
    → for each raw:
        validate(raw)                # ValidationResult
        parse(raw)                   # structured dict
        normalize(parsed)            # Rulezet-compatible dict
        → ParseResult(raw, validation, parsed, normalized, format_name)
```

### Parser registration — `parsers/__init__.py`

```python
from parsers.formats.yara_parser import YaraParser
# from parsers.formats.sigma_parser import SigmaParser  ← uncomment when ready

ALL_PARSERS = [
    YaraParser(),
    # SigmaParser(),
]
```

**To add a new format:** implement the parser → import it here → add instance to `ALL_PARSERS`. Nothing else changes.

---

## 6. The CLI — `main.py`

### Two modes

**Interactive menu** (no args):
```bash
python3 main.py
```
Numbered menu — accept number or name:
1. parse — parse rules from text or file
2. validate — validate syntax only
3. detect — auto-detect format
4. list — list registered parsers
5. new — scaffold a new parser
6. quit

**Direct commands:**
```bash
python3 main.py parse    -t 'rule X { condition: true }'
python3 main.py parse    -i rules.yar --json
python3 main.py parse    -i rules.yar --normalize
python3 main.py validate -t 'rule Bad { condition: bad }'
python3 main.py validate -i rules.yar -f yara
python3 main.py detect   -t 'alert tcp ...'
python3 main.py list
python3 main.py new sigma
```

### Internal conventions in `main.py`

- **Colour helpers** (no external dep): `c(text, *codes)`, `ok()`, `err()`, `info()`, `warn()` — ANSI codes at top of file.
- **`get_engine()`** — lazy import wrapper, always use this instead of importing the engine directly.
- **`_read_input(text, filepath)`** — resolves either `-t` text or `-i` file path into a string.
- **`_FakeArgs`** — used in interactive mode to reuse the same `cmd_*` functions as the argparse path.

---

## 7. YARA Parser — `parsers/formats/yara_parser.py`

**Libraries:** `yara-python` for compilation/validation · `plyara` for AST extraction.

### `can_handle()`
Regex lookahead for `rule <name> {` pattern, handles optional `global`/`private` modifiers.

### `validate()`
Retry loop up to 10 attempts on `yara.compile()`:
- `undefined identifier "pe"` → auto-inserts `import "pe"` via `insert_import_module()` and retries
- unknown external identifier → adds `"dummy"` string value and retries
- any other error → `ValidationResult(ok=False, errors=[error_msg])`
- success → `ValidationResult(ok=True, normalized_content=current_rule_text)`

### `split_rules()`
Regex-based (not character-level state machine). Finds all `rule <name> {` starts via `re.finditer`, slices content between consecutive match positions. Resilient: one broken rule doesn't stop the rest from being extracted.

### `parse()`
1. Calls `self.ply.clear()` — mandatory before every parse call, plyara is stateful
2. Calls `self.ply.parse_string(raw_rule)` to get the AST
3. Extracts metadata list → dict, detects CVEs in description via regex
4. On any exception → fallback regex extraction, returns full schema with safe empty defaults

### `normalize()`
Uses `.get()` with defaults on every key. Maps to the Rulezet schema.

### Helper function
`insert_import_module(rule_text, module_name)` — prepends `import "module"` if not already present.

---

## 8. Scaffold Tool — `utils/scaffold.py`

```bash
python3 -m utils.scaffold sigma
# or from interactive menu: choose "new"
```

Creates `parsers/formats/sigma_parser.py` with a complete TODO template:
- All abstract methods stubbed with `raise NotImplementedError` or safe stubs
- Correct imports (`from parsers.base import ...`)
- Full `parse()` schema with empty defaults in the fallback
- `normalize()` using `.get()` throughout

Refuses to overwrite an existing file. Prints next steps:
1. Implement all methods
2. Add `SigmaParser()` to `parsers/__init__.py → ALL_PARSERS`

**Target path:** `parsers/formats/<format_name>_parser.py` (not `rulecast/parsers/` — that was an old structure).

---

## 9. What Still Needs to Be Done

### Parsers to implement
- [ ] `sigma_parser.py` — YAML-based, use `pyyaml` + `pySigma`
- [ ] `suricata_parser.py` — single-line rules, use `suricataparser` lib
- [ ] `zeek_parser.py` — `.zeek` scripts
- [ ] `wazuh_parser.py` — XML-based
- [ ] `nse_parser.py` — Lua scripts (Nmap NSE)
- [ ] `crs_parser.py` — ModSecurity/OWASP CRS `.conf`
- [ ] `nova_parser.py` — custom format

### Testing
- [ ] `tests/` with pytest
- [ ] At least one valid + one invalid rule fixture per format
- [ ] Test `split_rules`, `validate`, `parse`, `normalize` independently (no file I/O needed — pass strings directly)

### Packaging
- [ ] `pyproject.toml` or `setup.py` for pip install / submodule use
- [ ] Add `venv/` and `__pycache__/` to `.gitignore`

---

## 10. Design Rules — Never Break These

| Rule | Detail |
|---|---|
| No I/O in parsers | `split_rules`, `validate`, `parse` take strings. File reading only in `engine.process_file()` or `main.py`. |
| Explicit registration | New parsers go in `parsers/__init__.py → ALL_PARSERS`. No `__subclasses__()` autodiscovery. |
| parse() ≠ normalize() | `parse()` extracts what the rule says. `normalize()` maps it to Rulezet's DB schema. Never merge them. |
| Full schema always | Both normal and fallback `parse()` paths must return ALL keys with safe defaults. |
| `.get()` in normalize() | Never `parsed_data['key']`. Always `parsed_data.get('key', default)`. |
| ply.clear() before parse | `plyara.Plyara()` is stateful. Call `self.ply.clear()` at the start of every `parse()` call. |
| English only | All code, comments, docstrings in English. |