#!/usr/bin/env python3
"""
RuleCast — Test Runner
Interactive tool to test parsers against rule files or pasted content.

Usage: python3 test_runner.py
"""

import os
import re
import sys
import json

# ── colour helpers ────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
WHITE  = "\033[97m"
MAGENTA = "\033[35m"

def c(text, *codes):
    return "".join(codes) + str(text) + RESET

def ok(msg):    print(c("  ✓ ", GREEN, BOLD) + msg)
def err(msg):   print(c("  ✗ ", RED,   BOLD) + msg)
def info(msg):  print(c("  · ", CYAN)        + msg)
def warn(msg):  print(c("  ! ", YELLOW, BOLD) + msg)
def title(msg): print(c(f"\n  {msg}", BOLD, WHITE))
def sep():      print(c("  " + "─" * 60, DIM))
def blank():    print()

# ── known test files ──────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

TEST_FILES = {
    "1": ("yara", os.path.join(SCRIPT_DIR, "formats", "test_yara_rules.yar")),
    # "2": ("sigma",    os.path.join(SCRIPT_DIR, "formats", "test_sigma_rules.yml")),
    # "3": ("suricata", os.path.join(SCRIPT_DIR, "formats", "test_suricata_rules.rules")),
    # "4": ("zeek",     os.path.join(SCRIPT_DIR, "formats", "test_zeek_scripts.zeek")),
    # "5": ("wazuh",    os.path.join(SCRIPT_DIR, "formats", "test_wazuh_rules.xml")),
    # "6": ("nse",      os.path.join(SCRIPT_DIR, "formats", "test_nse_scripts.nse")),
    # "7": ("crs",      os.path.join(SCRIPT_DIR, "formats", "test_crs_rules.conf")),
}

# ── expected counts parser ────────────────────────────────────────────────────

def _parse_expected(filepath: str) -> dict:
    """
    Read the EXPECTED RESULTS header from a test file.
    Looks for lines like:
      //   Total rules  : 99
      #    Valid        : 74
    Returns dict with keys: total, valid, invalid, incomplete (all int, -1 if not found)
    """
    expected = {"total": -1, "valid": -1, "invalid": -1, "incomplete": -1}
    if not filepath or not os.path.exists(filepath):
        return expected
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                for key in expected:
                    pattern = rf'(?://|#)\s+{key.capitalize()}\s+\w*\s*:\s*(\d+)'
                    m = re.search(pattern, line, re.IGNORECASE)
                    if m:
                        expected[key] = int(m.group(1))
    except Exception:
        pass
    return expected

# ── engine ────────────────────────────────────────────────────────────────────

def get_engine():
    root = os.path.dirname(SCRIPT_DIR)
    sys.path.insert(0, root)
    from parsers.engine import RuleCastEngine
    return RuleCastEngine()


def get_available_formats(engine):
    return [p["format"] for p in engine.list_parsers()]

# ── display ───────────────────────────────────────────────────────────────────

BANNER = f"""
{BOLD}{CYAN}  ╔══════════════════════════════════════╗
  ║     RuleCast — Parser Test Runner    ║
  ╚══════════════════════════════════════╝{RESET}
"""


def print_rule_result(index, total, fmt, raw, validation, parsed, normalized):
    blank()
    name = (
        parsed.get("identity", {}).get("name")
        or parsed.get("title")
        or "unknown"
    )
    status_icon = c("  ✓", GREEN, BOLD) if validation.ok else c("  ✗", RED, BOLD)
    print(
        f"{status_icon}  "
        f"{c(f'Rule {index}/{total}', BOLD)}  "
        f"{c(name, CYAN)}  "
        f"{c(f'[{fmt}]', DIM)}"
    )

    if not validation.ok:
        for e in validation.errors:
            print(f"     {c('error:', RED)} {e}")
    if validation.warnings:
        for w in validation.warnings:
            print(f"     {c('warn:', YELLOW)} {w}")

    status = parsed.get("status", "")
    if status == "parsing_error":
        parse_err = parsed.get("error", "")
        print(f"     {c('parse:', YELLOW)} fallback used — {parse_err[:80]}")

    tags = parsed.get("tags", [])
    if tags:
        print(f"     {c('tags:', DIM)} {', '.join(str(t) for t in tags)}")

    vulns = parsed.get("vulnerabilities", [])
    if vulns:
        print(f"     {c('CVEs:', YELLOW)} {', '.join(vulns)}")

    meta = parsed.get("metadata", {})
    if meta:
        items = list(meta.items())[:3]
        for k, v in items:
            print(f"     {c(k + ':', DIM)} {str(v)[:60]}")
        if len(meta) > 3:
            print(f"     {c(f'... +{len(meta)-3} more metadata fields', DIM)}")


def _check(label: str, found: int, expected: int):
    """Print a found vs expected line with pass/fail indicator."""
    if expected == -1:
        info(f"{label:<14}: {c(found, BOLD)}")
        return
    if found == expected:
        print(
            f"{c('  ✓ ', GREEN, BOLD)}"
            f"{label:<14}: {c(found, GREEN, BOLD)}"
            f"  {c(f'(expected {expected})', DIM)}"
        )
    else:
        print(
            f"{c('  ✗ ', RED, BOLD)}"
            f"{label:<14}: {c(found, RED, BOLD)}"
            f"  {c(f'expected {expected}, diff {found - expected:+d}', YELLOW)}"
        )


def print_summary(results, expected: dict):
    blank()
    sep()
    total      = len(results)
    valid      = sum(1 for r in results if r.validation.ok)
    invalid    = total - valid
    parsed_ok  = sum(1 for r in results if r.parsed.get("status") == "parsed")
    fallback   = sum(1 for r in results if r.parsed.get("status") == "parsing_error")

    title("Summary")
    _check("Total rules",  total,   expected["total"])
    _check("Valid",        valid,   expected["valid"])
    _check("Invalid",      invalid, expected["invalid"])
    info(f"{'Parsed (AST)':<14}: {c(parsed_ok, BOLD)}")
    info(f"{'Fallback':<14}: {c(fallback, YELLOW, BOLD) if fallback else c('0', DIM)}")

    if expected["total"] != -1:
        all_pass = (
            total == expected["total"]
            and valid == expected["valid"]
            and invalid == expected["invalid"]
        )
        blank()
        if all_pass:
            ok(c("All expected counts match.", GREEN, BOLD))
        else:
            err(c("Some counts differ from expected — check test file header.", RED))
    blank()


def print_detail_menu():
    blank()
    print(c("  What now?", BOLD))
    sep()
    print(f"  {c('j', CYAN, BOLD)}  Export full JSON results")
    print(f"  {c('n', CYAN, BOLD)}  Show normalized output only")
    print(f"  {c('f', CYAN, BOLD)}  Show only failed rules")
    print(f"  {c('r', CYAN, BOLD)}  Run again with different input")
    print(f"  {c('q', CYAN, BOLD)}  Quit")
    blank()

# ── step 1: choose format ─────────────────────────────────────────────────────

def step_choose_format(engine):
    formats = get_available_formats(engine)
    blank()
    title("Which format do you want to test?")
    sep()
    for i, fmt in enumerate(formats, 1):
        print(f"  {c(str(i), CYAN, BOLD)}  {c(fmt.upper(), BOLD)}")
    blank()

    while True:
        choice = input(c("  › ", CYAN, BOLD)).strip().lower()
        if choice.isdigit() and 1 <= int(choice) <= len(formats):
            return formats[int(choice) - 1]
        if choice in formats:
            return choice
        err(f"Invalid choice. Enter a number (1-{len(formats)}) or format name.")

# ── step 2: choose source ─────────────────────────────────────────────────────

def step_choose_source(fmt):
    blank()
    title("Input source")
    sep()
    print(f"  {c('p', CYAN, BOLD)}  Paste rules directly")
    print(f"  {c('f', CYAN, BOLD)}  Load from file")
    blank()

    while True:
        choice = input(c("  › ", CYAN, BOLD)).strip().lower()
        if choice in ("p", "paste"):
            return _read_paste(), None
        if choice in ("f", "file"):
            content, filepath = _read_file(fmt)
            return content, filepath
        err("Enter 'p' for paste or 'f' for file.")


def _read_paste():
    blank()
    print(c("  Paste your rules below.", BOLD))
    print(c("  Press Enter on a blank line then Ctrl+D (or Ctrl+Z on Windows) to finish.", DIM))
    blank()
    lines = []
    try:
        while True:
            lines.append(input())
    except EOFError:
        pass
    content = "\n".join(lines).strip()
    if not content:
        err("Nothing pasted.")
        sys.exit(1)
    return content


def _read_file(fmt):
    blank()
    title("File source")
    sep()

    matching = {k: v for k, v in TEST_FILES.items() if v[0] == fmt}
    if matching:
        print(c("  Known test files for this format:", DIM))
        for num, (f, path) in matching.items():
            exists = os.path.exists(path)
            status = c("✓", GREEN) if exists else c("✗ missing", RED)
            short = os.path.relpath(path, SCRIPT_DIR)
            print(f"  {c(num, CYAN, BOLD)}  {short}  {status}")
        blank()
        print(c("  Enter a number from above, or type a custom file path:", DIM))
    else:
        print(c(f"  No built-in test files for '{fmt}' yet.", YELLOW))
        print(c("  Enter the path to your rule file:", DIM))

    blank()

    while True:
        raw = input(c("  › ", CYAN, BOLD)).strip()
        if not raw:
            err("No input.")
            continue

        if raw in TEST_FILES:
            _, path = TEST_FILES[raw]
            if not os.path.exists(path):
                err(f"File not found: {path}")
                continue
            ok(f"Loaded: {os.path.relpath(path, SCRIPT_DIR)}")
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(), path

        path = os.path.expanduser(raw)
        if not os.path.exists(path):
            err(f"File not found: {path}")
            continue
        ok(f"Loaded: {path}")
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(), path

# ── step 3: run pipeline ──────────────────────────────────────────────────────

def run_pipeline(engine, content, fmt):
    blank()
    info(f"Format   : {c(fmt.upper(), BOLD)}")

    try:
        parser = engine.get_parser(fmt)
        if not parser:
            err(f"No parser registered for '{fmt}'.")
            sys.exit(1)

        raw_rules = parser.split_rules(content)
        info(f"Rules found : {c(len(raw_rules), BOLD)}")
        sep()

        results = []
        for raw in raw_rules:
            validation = parser.validate(raw)
            parsed     = parser.parse(raw)
            normalized = parser.normalize(parsed)

            from parsers.engine import ParseResult
            results.append(ParseResult(raw, validation, parsed, normalized, fmt))

        return results, parser

    except Exception as e:
        err(f"Pipeline error: {e}")
        sys.exit(1)

# ── step 4: display + post menu ───────────────────────────────────────────────

def display_results(results, fmt, expected: dict):
    total = len(results)
    for i, r in enumerate(results, 1):
        print_rule_result(i, total, fmt, r.raw, r.validation, r.parsed, r.normalized)
    print_summary(results, expected)


def post_menu(results, fmt):
    while True:
        print_detail_menu()
        choice = input(c("  › ", CYAN, BOLD)).strip().lower()

        if choice == "j":
            data = [r.to_dict() for r in results]
            out_path = os.path.join(SCRIPT_DIR, f"results_{fmt}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            ok(f"Saved to {out_path}")

        elif choice == "n":
            blank()
            title("Normalized output")
            sep()
            for r in results:
                name = r.normalized.get("title") or "unknown"
                print(f"\n  {c(name, CYAN, BOLD)}")
                for k, v in r.normalized.items():
                    if k != "title" and v:
                        print(f"  {c(k.ljust(14), DIM)}: {str(v)[:80]}")

        elif choice == "f":
            failed = [r for r in results if not r.validation.ok]
            if not failed:
                ok("No failed rules!")
            else:
                blank()
                title(f"{len(failed)} failed rule(s)")
                sep()
                for r in failed:
                    name = r.parsed.get("identity", {}).get("name") or "unknown"
                    print(f"\n  {c('✗', RED, BOLD)}  {c(name, BOLD)}")
                    for e in r.validation.errors:
                        print(f"     {c(e, RED)}")
                    blank()
                    print(c("  Raw content preview:", DIM))
                    preview = r.raw[:200].replace("\n", "\n  ")
                    print(c(f"  {preview}{'...' if len(r.raw) > 200 else ''}", DIM))

        elif choice in ("r", "restart"):
            return "restart"

        elif choice in ("q", "quit", "exit"):
            blank()
            info("Goodbye.")
            blank()
            return "quit"

        else:
            err(f"Unknown option: '{choice}'")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    try:
        engine = get_engine()
    except ImportError as e:
        print(c(f"  [error] Could not load engine: {e}", RED))
        print(c("  Make sure you run this from the rulezet-cast root directory.", DIM))
        sys.exit(1)

    while True:
        fmt              = step_choose_format(engine)
        content, fpath   = step_choose_source(fmt)
        expected         = _parse_expected(fpath)
        results, _       = run_pipeline(engine, content, fmt)
        display_results(results, fmt, expected)
        action           = post_menu(results, fmt)

        if action == "quit":
            break


if __name__ == "__main__":
    main()