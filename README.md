# finding-forge

[![tests](https://github.com/kubakozub/finding-forge/actions/workflows/tests.yml/badge.svg)](https://github.com/kubakozub/finding-forge/actions/workflows/tests.yml)

**Turn a verified finding into a clean, complete, submission-ready report, with accurate CVSS 3.1 scoring and a pre-submit lint that catches missing sections and leaked secrets.**

`finding-forge` encodes one rule of good bug-bounty work: **one clean, reproducible report beats ten noisy ones.** It scaffolds the sections triagers actually read, scores severity with a CVSS v3.1 implementation that matches the FIRST calculator to the decimal, and gates your draft before you paste it into HackerOne or Bugcrowd so a stray `Authorization:` header or an empty *Steps to Reproduce* never goes out under your name.

- **Zero dependencies.** Pure Python standard library (`argparse`, `re`, `json`, `math`). Python 3.9+.
- **No network, no telemetry, no secrets.** It reads your draft locally and prints a verdict. Nothing leaves your machine.
- **CI-friendly.** `lint` exits non-zero on hard problems, so it drops straight into a pre-commit hook or pipeline.

---

## Why report quality is the whole game

Triage is a queue. A report that is missing a repro, hand-waves impact, or forces the triager to guess your CVSS gets bounced to *Needs More Info*, and every round-trip is days of latency and a dent in your signal. A report that lands complete on the first read gets triaged fast, scored fairly, and paid. `finding-forge` removes the three things that most often go wrong:

1. **Missing structure**, you forget a section under time pressure. The template won't let you.
2. **Wrong severity**: hand-computed CVSS is error-prone; a wrong vector invites a downgrade. The math here is exact.
3. **Leaked material**, you paste real traffic into the PoC and ship a live token or a customer's PII. The lint catches it first.

---

## Install

```bash
git clone https://github.com/jakubkozub/finding-forge
cd finding-forge
pip install .        # provides the `finding-forge` command
```

Or run it straight from a checkout with no install at all:

```bash
python -m finding_forge --help
```

---

## Usage

### 1. `new`: scaffold a report

```bash
finding-forge new --type idor --title "IDOR in /api/invoices lets users read others' invoices" -o report.md
```

Supported bug-class templates:

| `--type`                 | Class                                             |
|--------------------------|---------------------------------------------------|
| `idor`                   | IDOR / Broken Object-Level Authorization          |
| `broken-access-control`  | Broken Access Control / Privilege Escalation      |
| `auth-bypass`            | Authentication Bypass                             |
| `xss`                    | Cross-Site Scripting (reflected / stored / DOM)   |
| `ssrf`                   | Server-Side Request Forgery                       |
| `sqli`                   | SQL Injection                                     |
| `csrf`                   | Cross-Site Request Forgery                        |
| `info-disclosure`        | Sensitive Information Disclosure                  |
| `generic`                | Anything else (neutral skeleton)                  |

Every template emits the same skeleton triagers expect (**Title, Summary, Affected Asset, CVSS, Impact, Steps to Reproduce, Proof of Concept, Remediation, References**), pre-filled with class-specific hints and a *suggested* CVSS vector that is scored live:

```markdown
# IDOR in <endpoint> allows reading/modifying other users' <object>

> Bug class: **IDOR / Broken Object-Level Authorization**. DRAFT. Fill every `<TODO: ...>`, redact real secrets, and delete this banner before submitting.

## Summary

The `<TODO: endpoint>` endpoint authorizes the *session* but not *ownership* of the
requested object. Any authenticated user can read `<TODO: describe object>` ...

## CVSS

- Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- Base score: **6.5 (Medium)**
...
```

Fill in every `<TODO: ...>`, drop in your PoC, and you have a report. Placeholders are written so the linter can spot anything you left behind.

### 2. `cvss`: score or build a vector

Score an existing vector string:

```console
$ finding-forge cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
Vector      : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Base score  : 6.1
Severity    : Medium
```

Build one from individual metrics (handy when you're reasoning about impact metric by metric):

```console
$ finding-forge cvss --av N --ac L --pr N --ui N --s U --c H --i H --a H
Vector      : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Base score  : 9.8
Severity    : Critical
```

Add `--explain` for the expanded metric names, or `--json` for machine-readable output:

```console
$ finding-forge cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" --json
{
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "base_score": 7.5,
  "severity": "High",
  "metrics": { "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N" }
}
```

The base-score math follows the FIRST CVSS v3.1 specification exactly, including the scope-changed impact term and the integer-scaled `Roundup` function, and is unit-tested against the official calculator for a spread of canonical vectors (7.5 High, 9.8 / 10.0 Critical, 6.1 Medium, 3.1 Low, 0.0 None, and more).

### 3. `lint`: the pre-submit gate

```console
$ finding-forge lint report.md
finding-forge lint - report.md

Sections
  [FAIL] Steps to Reproduce - required section missing
  [PASS] Title - IDOR in invoice download allows reading ...
  [PASS] Summary - present
  ...

Secrets & PII
  [FAIL] JWT token - eyJhbGciOiJI...sR8U (line 16)
  [FAIL] Authorization header - Authorizatio...sR8U (line 16)
  [FAIL] Bearer token - Bearer eyJhb...sR8U (line 16)
  [FAIL] Cookie header - Cookie: sess...2543 (line 17)

CVSS
  [PASS] CVSS vector - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High)

Result: FAIL - 5 error(s), 2 warning(s)
```

`lint` checks three things:

- **Completeness**, every expected section is present and non-empty (placeholder-only sections don't count).
- **Secrets & PII**: leaked JWTs, AWS/GitHub/Slack/Google/Stripe keys, private-key blocks, `Authorization` / `Cookie` / Bearer / Basic-auth headers with real values, high-entropy strings, unredacted emails, and Luhn-valid card numbers. Redacted placeholders (`<token>`, `$SESSION`, `example.com`) are recognised and left alone, so a properly sanitised report stays quiet.
- **Quality**, a CVSS vector is present and actually parses, repro steps are enumerated, and there's no vague filler (`might`, `could possibly`, ...) or leftover `<TODO>`.

### How the gate works

| Level     | Meaning                                              | Exit code                          |
|-----------|------------------------------------------------------|------------------------------------|
| **error** | Hard problem: missing section, leaked secret, no CVSS | non-zero, **blocks submission**   |
| **warn**  | Worth a look: email/PII, filler, leftover `<TODO>`    | zero by default; non-zero with `--strict` |

Use it as a real gate: for example in a pre-commit hook or CI:

```bash
finding-forge lint report.md --strict || {
  echo "Report not submission-ready. Fix the items above."; exit 1;
}
```

Add `--json` for tooling and `--quiet` to show only problems.

---

## How it fits the workflow

`finding-forge` owns the **last mile**: verified finding → polished report → clean submission.

```
   recon / testing         finding-forge              submit
  ┌───────────────┐   ┌────────────────────────┐   ┌──────────┐
  │  you find and │   │ new  → draft the report │   │ HackerOne│
  │  VERIFY a bug │──▶│ cvss → score it right   │──▶│ Bugcrowd │
  │  (out of scope│   │ lint → gate before send │   │ VDP / ...│
  │   for this    │   └────────────────────────┘   └──────────┘
  │   tool)       │
  └───────────────┘
```

It pairs naturally with a **redaction step** in front of the lint: run your traffic captures through a redactor to strip live tokens and PII, then let `finding-forge lint` act as the backstop that fails the submission if anything slipped through. The lint is deliberately your *seatbelt*, not your only line of defence, you should never be relying on it to notice the secret, but you'll be glad it does.

---

## A worked example

[`examples/wordpress-media-finalize.md`](examples/wordpress-media-finalize.md) is a finished
report for a real finding: HackerOne [#3931777](https://hackerone.com/reports/3931777), a
CVSS 9.9 in WordPress core where the lowest role allowed to upload files could delete
`wp-config.php`, and a WordPress without `wp-config.php` hands its installer to anyone. It
was resolved and paid, and it is written in the shape this tool produces.

It is worth reading for two things the template cannot supply for you. The first is the
severity argument: the report states *why* Scope is Changed rather than asserting a number,
and gives the score both ways so a triager can disagree in one step.

```console
$ finding-forge cvss "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
Vector      : CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
Base score  : 9.9
Severity    : Critical

$ finding-forge cvss "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
Base score  : 8.8
Severity    : High
```

The second is the impact chain. The finding on its own is an arbitrary file deletion, which
is serious but not a 9.9. What earns the score is the sentence after it: with that file gone,
the installer answers 200 on a site that was already configured. A report that stops at the
defect leaves the triager to discover the consequence, and a triager who has to do that work
is a triager who downgrades.

The example passes the gate, including under `--strict`:

```console
$ finding-forge lint --strict examples/wordpress-media-finalize.md
Sections
  [PASS] Title - Author can delete wp-config.php through ...ller
  [PASS] Summary - present
  ...
CVSS
  [PASS] CVSS vector - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9 (Critical)

Result: PASS - 0 error(s), 0 warning(s) (--strict: warnings fail the gate)
```

The proof-of-concept section carries the request shape but not the traversal string. That is
deliberate: the example exists to show what a finished report looks like, and an exploit
primitive for a patched core bug adds nothing to that. The detections for the same chain,
with the log lines that should and should not fire them, are in
[detections](https://github.com/kubakozub/detections).

---

## Development

```bash
python -m unittest discover -v     # 42 tests, standard-library unittest
```

The suite asserts the CVSS math against known-correct base scores, that every template renders the full section set, and that the lint fails a report missing *Steps to Reproduce* and carrying a planted JWT/Cookie while passing a clean, complete report.

## License

MIT © 2026 Jakub Kozub. See [LICENSE](LICENSE).
