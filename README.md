# javscan

**Advanced Java Static Application Security Testing (SAST), written in Rust.**

javscan parses Java with a real AST (tree-sitter) and runs an intraprocedural **taint analysis** to trace user-controlled data from sources (servlet request accessors, Spring MVC annotated parameters, `main(String[] args)`, stdin) through assignments, string concatenation, `StringBuilder`, and `String` transformations into dangerous sinks — while recognizing sanitizers (OWASP Java Encoder, Apache commons-text escapes, `URLEncoder`, numeric parsing, `UUID.fromString`, `FilenameUtils.getName`) to keep false positives down.

Sister project of [sapyscan](https://github.com/AYAN-AMBESH/sapyscan) (Python SAST).

## Highlights

- **28 security rules** with CWE and OWASP Top 10 (2021) mappings
- **AST-based taint tracking**, not regex grepping — a `PreparedStatement` with bind parameters or an `Encode.forHtml()` call produces no noise
- **Fast**: parallel scanning via rayon; ~60k lines of Java in about a second
- **4 output formats**: colored console, JSON, **SARIF 2.1.0** (GitHub Code Scanning ready), and a self-contained interactive **HTML dashboard**
- **Baseline diffing**: snapshot existing findings, then fail CI only on *new* issues (fingerprints survive line-number shifts)
- **Inline suppression** (`// nosec`, `// javscan:ignore JS101`), project config file, severity/confidence levels, configurable exit codes
- Auto-skips test sources (`src/test`, `*Test.java`) and build/generated directories
- **Type-aware sink matching** and **trust-boundary tagging** (see below) — a dangerous *name* is not treated as a dangerous *call*

## Precision: type resolution and trust boundaries

Name-only matching is the dominant source of SAST false positives. javscan
resolves three things before it reports:

**1. The receiver's type, not its name.** `.load()` only fires when the
receiver actually resolves to `org.yaml.snakeyaml.Yaml`. Hardened wrappers
(`YamlProcessor`, `YamlPropertySourceLoader` and their subclasses) build their
parser with a `SafeConstructor` and are allow-listed. The construction site is
inspected per-variable, so `new Yaml(new SafeConstructor(...))` is silent while
`new Yaml(new Constructor(...))` is CRITICAL. Where a `pom.xml`/`build.gradle`
declares SnakeYAML >= 2.0 — which rejects global type tags by default — a bare
`new Yaml()` drops to INFO.

**2. The method's owner, not its name.**
`SecurityJackson2Modules.enableDefaultTyping(mapper)` installs an allow-list
`PolymorphicTypeValidator`; it is a different symbol from
`ObjectMapper#enableDefaultTyping` and is not reported.
`activateDefaultTyping(...)` with a real validator is INFO ("confirm the
allow-list scope"); with `LaissezFaireSubTypeValidator`, CRITICAL.

**3. The value, not the identifier.** `hardcoded-secret` requires the *value*
to look like key material. Names whose segments denote a role — `*_TYPE`,
`*_PREFIX`, `*_REGEX`, `*_REASON`, `*_HEADER`, … — are domain nouns, not
credential claims. URIs, regexes, namespace prefixes, label vocabulary
(`Opaque`, `Bearer`) and lowercase word phrases are rejected regardless of
entropy; long high-entropy strings and mixed-character-class passwords are
reported.

**Trust source.** Every finding carries a `source` tag —
`NETWORK`, `LOCAL_FS`, `PLUGIN`, `THEME`, `CONFIG`, `CONSTANT` or `UNKNOWN`.
Only `NETWORK` (and `UNKNOWN`, which may yet be network) keeps full severity;
the others drop two or three steps and carry a note explaining why. A dangerous
API reading a file this same class serialized with `ObjectOutputStream` is a
self-serialized round trip: still reported, but LOW, because poisoning it
requires local write access first. SpEL evaluated against a
`SimpleEvaluationContext` — which forbids the `T(...)` type references and
constructor calls SpEL RCE needs — is not reported at all.

`tests/regression.rs` pins each of these as a golden fixture, positive and
negative, so a precision fix cannot silently become a recall regression.

## Rules

| ID | Rule | Severity | CWE |
|----|------|----------|-----|
| JS101 | sql-injection | CRITICAL | CWE-89 |
| JS102 | command-injection | CRITICAL | CWE-78 |
| JS103 | ldap-injection | HIGH | CWE-90 |
| JS104 | xpath-injection | HIGH | CWE-643 |
| JS105 | spel-injection | CRITICAL | CWE-917 |
| JS106 | script-engine-injection | CRITICAL | CWE-94 |
| JS107 | log-injection | LOW | CWE-117 |
| JS201 | cross-site-scripting | HIGH | CWE-79 |
| JS202 | open-redirect | MEDIUM | CWE-601 |
| JS203 | ssrf | HIGH | CWE-918 |
| JS204 | insecure-cookie | MEDIUM | CWE-614 |
| JS205 | csrf-disabled | HIGH | CWE-352 |
| JS206 | permissive-cors | MEDIUM | CWE-942 |
| JS207 | cleartext-http | LOW | CWE-319 |
| JS301 | weak-hash (MD5/SHA-1) | HIGH | CWE-328 |
| JS302 | weak-cipher (DES/RC4/ECB) | HIGH | CWE-327 |
| JS303 | weak-random | LOW–HIGH | CWE-330 |
| JS304 | hardcoded-crypto-material | HIGH | CWE-321 |
| JS305 | trust-all-tls | CRITICAL | CWE-295 |
| JS306 | weak-key-size | MEDIUM | CWE-326 |
| JS401 | hardcoded-secret | HIGH–CRITICAL | CWE-798 |
| JS402 | jwt-weak-signing | HIGH | CWE-347 |
| JS501 | insecure-deserialization | CRITICAL | CWE-502 |
| JS502 | xxe | HIGH | CWE-611 |
| JS601 | path-traversal | HIGH | CWE-22 |
| JS602 | zip-slip | HIGH | CWE-22 |
| JS701 | redos | MEDIUM | CWE-1333 |
| JS702 | unsafe-reflection | HIGH | CWE-470 |

Run `javscan --rules` for full descriptions.

## Install

```sh
cargo install --path .
# or
cargo build --release   # binary at target/release/javscan
```

## Usage

```sh
# scan a project (console output)
javscan src/

# interactive HTML dashboard
javscan . --format html --output report.html

# SARIF for GitHub Code Scanning
javscan . --format sarif --output results.sarif

# machine-readable JSON
javscan . --format json --output results.json

# only high and critical findings; fail CI on critical
javscan . --min-severity high --fail-on critical

# disable rules, exclude paths, scan tests too
javscan . --disable JS207 --disable log-injection --exclude "**/generated/**" --include-tests
```

### Baseline workflow (adopting javscan on an existing codebase)

```sh
javscan . --write-baseline .javscan-baseline.json   # accept current findings
javscan . --baseline .javscan-baseline.json          # from now on: only NEW findings
```

Fingerprints hash the rule, file, and normalized code line — not line numbers — so unrelated edits don't resurface baselined findings.

### Inline suppression

```java
Runtime.getRuntime().exec(cmd); // nosec
stmt.executeQuery(sql);         // javscan:ignore JS101
// javscan:ignore JS102,JS601   (a comment on the line above also applies)
```

### Configuration — `.javscan.json` at the project root

```json
{
  "exclude": ["**/generated/**", "**/legacy/**"],
  "disabled_rules": ["JS207"],
  "min_severity": "low",
  "include_tests": false,
  "fail_on": "high"
}
```

CLI flags override the config file.

### Exit codes

- `0` — no findings at or above the `--fail-on` threshold (default `high`); use `--fail-on never` to always exit 0
- `1` — findings at/above the threshold
- `2` — execution error (bad baseline, unwritable output, ...)

## How the taint analysis works

1. **Sources** seed taint: parameters annotated `@RequestParam` / `@PathVariable` / `@RequestBody` / `@RequestHeader` / `@CookieValue`, parameters of `@GetMapping`-style handlers and servlet `doGet`/`doPost`, `HttpServletRequest` accessors (`getParameter`, `getHeader`, `getQueryString`, ...), `main` args, `Scanner`/`BufferedReader` reads.
2. **Propagation** runs to a fixpoint per method: assignments, `+` concatenation, `StringBuilder.append/insert`, `String.format/valueOf/substring/replace/...`, ternaries, casts, enhanced-for over tainted collections, and (heuristically) calls that take tainted arguments.
3. **Sanitizers** kill taint: OWASP `Encode.forHtml/forJavaScript/...`, ESAPI encoders, commons-text `escapeHtml4/escapeXml/...`, `URLEncoder.encode`, `Integer.parseInt` and friends, `UUID.fromString`, `FilenameUtils.getName`, `Pattern.quote`.
4. **Sinks** are rule-specific (SQL execute, `Runtime.exec`, response writers, file constructors, ...). A tainted sink argument yields a high-confidence finding; dynamic-but-unproven concatenation yields a medium/low-confidence one at reduced severity.

Analysis is intraprocedural (per method) with heuristic call propagation — the classic SAST precision/recall tradeoff at high scan speed.

Taint answers *"is this attacker-controlled?"*, which is not the same as *"is
this safe?"* — an untainted value may still come from a local file, a plugin
descriptor or a theme template. The trust-source classifier fills that gap for
rules whose sink is dangerous regardless of the caller (native deserialization,
SpEL, reflection), so those findings are ranked by reachability rather than
suppressed or left at CRITICAL.

## Example

```text
examples/vulnerable/UserController.java
  32:13  CRITICAL  JS101 [sql-injection] (high confidence, CWE-89)
      User-controlled data reaches SQL sink `executeQuery()`; the query is attacker-influenced.
      > stmt.executeQuery(query);
```

The `examples/` directory contains intentionally vulnerable and clean files used as the acceptance corpus; the clean file produces zero findings.

## License

MIT
