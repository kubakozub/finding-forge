"""Lint / pre-submit gate tests."""

import io
import unittest
from contextlib import redirect_stdout

from finding_forge import cli, lint

# A complete, clean, submission-ready report (no secrets, no placeholders).
CLEAN_REPORT = """\
# IDOR in invoice download allows reading other users' invoices

## Summary
The invoice download endpoint authorizes by session but not by object
ownership, so any authenticated user can download any invoice by ID.

## Affected Asset
- Target: Acme (production)
- Endpoint: GET https://app.acme.example/api/invoices/{id}/pdf
- Parameter: id (path)

## CVSS
- Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- Base score: 6.5 (Medium)

## Impact
An authenticated attacker can enumerate invoice IDs and download PDF
invoices belonging to other customers, exposing names and addresses.

## Steps to Reproduce
1. Log in as user A and note your invoice URL.
2. Replace the numeric id in the path with another customer's id.
3. Observe that the PDF for user B is returned with HTTP 200.

## Proof of Concept
Request with user A's session returns user B's invoice:
curl -H "Cookie: session=$SESSION" https://app.acme.example/api/invoices/1002/pdf

## Remediation
Enforce an ownership check on the invoice id server-side: confirm the
authenticated user owns the requested invoice before returning it.

## References
- https://owasp.org/www-project-top-ten/ (A01:2021 Broken Access Control)
"""

# Missing "Steps to Reproduce" AND carrying a planted JWT + real Cookie value.
BAD_REPORT = """\
# Test report missing steps

## Summary
Something is wrong here.

## Affected Asset
- Endpoint: https://app.example.com/api/x

## CVSS
- Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Impact
Data exposure of customer records.

## Proof of Concept
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
Cookie: sessionid=8f14e45fceea167a5a36dedd4bea2543

## Remediation
Fix the authorization check.

## References
- none
"""


def categories(checks):
    return {c.category for c in checks}


class TestCleanReport(unittest.TestCase):
    def test_clean_report_passes(self):
        result = lint.lint_text(CLEAN_REPORT)
        self.assertEqual(result.errors, [],
                         "clean report should have no errors, got: %r"
                         % [(c.category, c.message) for c in result.errors])
        self.assertTrue(result.ok())
        self.assertEqual(result.exit_code(), 0)

    def test_clean_report_has_no_warnings_either(self):
        # The redaction/allowlist logic must not flag $SESSION or example.com.
        result = lint.lint_text(CLEAN_REPORT)
        self.assertEqual(result.warnings, [],
                         "unexpected warnings: %r"
                         % [(c.category, c.message) for c in result.warnings])

    def test_clean_report_cvss_recognised(self):
        result = lint.lint_text(CLEAN_REPORT)
        cvss_checks = [c for c in result.passes if c.kind == "cvss"]
        self.assertEqual(len(cvss_checks), 1)
        self.assertIn("6.5", cvss_checks[0].message)


class TestBadReport(unittest.TestCase):
    def setUp(self):
        self.result = lint.lint_text(BAD_REPORT)

    def test_fails_the_gate(self):
        self.assertFalse(self.result.ok())
        self.assertEqual(self.result.exit_code(), 1)
        self.assertTrue(self.result.errors)

    def test_missing_steps_to_reproduce_flagged(self):
        section_errs = [c for c in self.result.errors if c.kind == "section"]
        self.assertTrue(
            any(c.category == "Steps to Reproduce" for c in section_errs),
            "should flag the missing Steps to Reproduce section")

    def test_planted_jwt_flagged(self):
        secret_errs = [c for c in self.result.errors if c.kind == "secret"]
        cats = categories(secret_errs)
        self.assertIn("JWT token", cats)

    def test_planted_cookie_flagged(self):
        secret_errs = [c for c in self.result.errors if c.kind == "secret"]
        self.assertIn("Cookie header", categories(secret_errs))


class TestSecretDetection(unittest.TestCase):
    def _secret_categories(self, text):
        r = lint.lint_text(text)
        return {c.category for c in r.checks if c.kind == "secret"}

    def test_aws_access_key(self):
        self.assertIn("AWS access key id",
                      self._secret_categories("key AKIAIOSFODNN7EXAMPLE here"))

    def test_private_key_block(self):
        self.assertIn(
            "Private key block",
            self._secret_categories("-----BEGIN RSA PRIVATE KEY-----"))

    def test_github_token(self):
        text = "token ghp_" + "a" * 36
        self.assertIn("GitHub token", self._secret_categories(text))

    def test_redacted_bearer_not_flagged(self):
        # `<token>` and $VARS are placeholders, not leaks.
        cats = self._secret_categories("Authorization: Bearer <token>")
        self.assertEqual(cats, set())
        cats2 = self._secret_categories("Cookie: session=$SESSION")
        self.assertEqual(cats2, set())

    def test_luhn_valid_pan_flagged(self):
        # 4111 1111 1111 1111 is the canonical Luhn-valid test PAN.
        cats = self._secret_categories("card 4111 1111 1111 1111 on file")
        self.assertIn("Payment card number (Luhn-valid)", cats)

    def test_luhn_invalid_number_not_flagged(self):
        cats = self._secret_categories("order id 1234 5678 9012 3456 here")
        self.assertNotIn("Payment card number (Luhn-valid)", cats)


class TestQualityChecks(unittest.TestCase):
    def test_missing_cvss_is_error(self):
        text = "# t\n## Summary\nx\n## Impact\ny\n"
        result = lint.lint_text(text)
        self.assertTrue(any(c.kind == "cvss" and c.level == "error"
                            for c in result.checks))

    def test_vague_filler_warned(self):
        result = lint.lint_text(CLEAN_REPORT.replace(
            "any authenticated user can download",
            "an attacker might possibly download"))
        self.assertTrue(any(c.category == "Vague filler"
                            for c in result.warnings))

    def test_email_pii_warned_but_not_error(self):
        text = CLEAN_REPORT.replace(
            "exposing names and addresses.",
            "exposing victim contact jane.doe@corp.co here.")
        result = lint.lint_text(text)
        self.assertTrue(any(c.category == "Email address"
                            for c in result.warnings))
        self.assertEqual(result.errors, [])

    def test_strict_makes_warnings_fail(self):
        text = CLEAN_REPORT.replace("HTTP 200.", "HTTP 200. <TODO: confirm>")
        result = lint.lint_text(text)
        self.assertTrue(result.ok(strict=False))   # warnings only
        self.assertFalse(result.ok(strict=True))   # strict fails


class TestLintCLI(unittest.TestCase):
    def _write(self, text):
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".md")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_cli_clean_exit_zero(self):
        path = self._write(CLEAN_REPORT)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["lint", path])
        self.assertEqual(rc, 0)
        self.assertIn("Result: PASS", buf.getvalue())

    def test_cli_bad_exit_nonzero(self):
        path = self._write(BAD_REPORT)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["lint", path])
        self.assertEqual(rc, 1)
        self.assertIn("Result: FAIL", buf.getvalue())

    def test_cli_json_output(self):
        import json
        path = self._write(CLEAN_REPORT)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.main(["lint", path, "--json"])
        data = json.loads(buf.getvalue())
        self.assertTrue(data["ok"])
        self.assertEqual(data["errors"], 0)


if __name__ == "__main__":
    unittest.main()
