"""Report scaffolding (`new` / templates) tests."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from finding_forge import cli, cvss, templates

REQUIRED_HEADINGS = [
    "## Summary",
    "## Affected Asset",
    "## CVSS",
    "## Impact",
    "## Steps to Reproduce",
    "## Proof of Concept",
    "## Remediation",
    "## References",
]


class TestTemplates(unittest.TestCase):
    def test_idor_has_all_sections(self):
        report = templates.render("idor")
        self.assertTrue(report.startswith("# "), "report needs an H1 title")
        for heading in REQUIRED_HEADINGS:
            self.assertIn(heading, report,
                          "idor template missing %s" % heading)

    def test_every_class_renders_all_sections(self):
        for name in templates.CLASS_ORDER:
            with self.subTest(bug_class=name):
                report = templates.render(name)
                self.assertTrue(report.startswith("# "))
                for heading in REQUIRED_HEADINGS:
                    self.assertIn(heading, report)

    def test_cvss_section_carries_a_real_score(self):
        # The scaffold pre-computes the suggested vector's score.
        report = templates.render("idor")
        self.assertIn("CVSS:3.1/", report)
        self.assertIn("6.5 (Medium)", report)  # the idor default vector

    def test_every_suggested_vector_parses(self):
        for name, spec in templates.CLASSES.items():
            with self.subTest(bug_class=name):
                # Must not raise.
                score, _sev, _m = cvss.score_vector(spec["cvss"])
                self.assertGreaterEqual(score, 0.0)

    def test_title_override(self):
        report = templates.render("xss", title="My reflected XSS")
        self.assertTrue(report.startswith("# My reflected XSS\n"))

    def test_unknown_class_raises(self):
        with self.assertRaises(KeyError):
            templates.render("not-a-real-class")


class TestNewCommand(unittest.TestCase):
    def test_new_stdout_contains_sections(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["new", "--type", "idor"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        for heading in REQUIRED_HEADINGS:
            self.assertIn(heading, out)

    def test_new_writes_file(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.md")
            with redirect_stderr(io.StringIO()):
                rc = cli.main(["new", "--type", "ssrf", "-o", path])
            self.assertEqual(rc, 0)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("## Steps to Reproduce", text)
            self.assertIn("SSRF", text)

    def test_new_title_flag(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.main(["new", "--type", "sqli", "--title", "SQLi in search"])
        self.assertIn("# SQLi in search", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
