**YARA** — déjà fait ✅

- `yara-python` — compilation + validation
- `plyara` — AST extraction

---

**Sigma**

- [`pySigma`](https://github.com/SigmaHQ/pySigma) — `pip install pysigma` — parse + validate + convert. Officiel SigmaHQ. Inclut `SigmaCollection.from_yaml()` et `SigmaValidator`.

---

**Suricata**

- [`suricataparser`](https://github.com/m-chrome/py-suricataparser) — `pip install suricataparser` — parse + génère des règles Snort/Suricata. API stable et frozen.
- [`suricata-check`](https://pypi.org/project/suricata-check/) — `pip install suricata-check` — validateur statique avec codes d'erreur structurés, sans installation de Suricata.
- [`idstools`](https://github.com/jasonish/py-idstools) — `pip install idstools` — parse multi-lignes, gestion de fichiers `.rules`.

---

**Zeek**

- [`zeekscript`](https://github.com/zeek/zeekscript) — `pip install zeekscript` — parser officiel Zeek basé sur Tree-Sitter. Fournit un AST + détection d'erreurs de parsing.

---

**Wazuh** (XML)

- Pas de lib dédiée sur PyPI — les règles sont du XML pur → utiliser `xml.etree.ElementTree` (stdlib) ou `lxml`.
- [`wazuh-linter`](https://github.com/pyToshka/wazuh-linter) — `pip install "wazuh-linter[api] @ git+..."` — validateur statique de decoders/rules XML Wazuh.

---

**NSE** (Lua)

- [`luaparser`](https://github.com/boolangery/py-lua-parser) — `pip install luaparser` — parse Lua en AST Python. Supporte Lua 5.3/5.4. Permet d'extraire les metadata NSE (`description`, `categories`, `author`...).
- [`lupa`](https://github.com/scoder/lupa) — `pip install lupa` — exécute du Lua dans Python via LuaJIT. Utile si tu veux évaluer le script, pas juste le parser.

---

**CRS** (ModSecurity/OWASP)

- [`secrules-parsing`](https://pypi.org/project/secrules-parsing/) — `pip install secrules-parsing` — parse les fichiers `.conf` SecRule de l'OWASP CRS avec textX.

---

**Nova** — format custom, aucune lib existante → parsing manuel à implémenter.
