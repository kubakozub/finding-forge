"""CVSS v3.1 base-score correctness.

Every expected value here is taken from the official FIRST CVSS v3.1
calculator. If any of these drift, the scoring math is wrong.
"""

import unittest

from finding_forge import cvss

# (vector, expected_score, expected_severity) — verified against FIRST.
CANONICAL = [
    # The textbook 7.5 example (unauth confidentiality-only, network).
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
    # Classic unauth RCE-class, scope unchanged -> 9.8 Critical.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    # Scope changed, everything high -> the 10.0 ceiling.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
    # The canonical reflected-XSS vector -> 6.1 Medium (scope changed).
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    # A Low example.
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "Low"),
    # No impact -> 0.0 None.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
    # Local privilege escalation -> 7.8 High.
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    # High privileges required knocks the same impact down to 7.2.
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "High"),
    # Authenticated IDOR read (the default idor template vector).
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "Medium"),
    # Physical, high complexity, tiny impact -> 1.6 Low (exercises AV:P/AC:H).
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"),
    # Adjacent + scope changed all-high -> 9.6 (NOT 10.0; AV:A < AV:N).
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.6, "Critical"),
    # Scope-changed PR:L uses the 0.68 weight (not 0.62) -> 9.9 Critical.
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "Critical"),
]


class TestBaseScore(unittest.TestCase):
    def test_canonical_scores(self):
        for vector, exp_score, exp_sev in CANONICAL:
            with self.subTest(vector=vector):
                score, sev, _ = cvss.score_vector(vector)
                self.assertAlmostEqual(
                    score, exp_score, places=1,
                    msg="%s -> %s, expected %s" % (vector, score, exp_score))
                self.assertEqual(sev, exp_sev)

    def test_specific_75_high(self):
        # The exact example named in the tool spec.
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        self.assertEqual(cvss.base_score(v), 7.5)
        self.assertEqual(cvss.severity(cvss.base_score(v)), "High")

    def test_prefixless_vector(self):
        # The CVSS:3.1/ prefix is optional.
        self.assertEqual(
            cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)

    def test_case_insensitive(self):
        self.assertEqual(
            cvss.base_score("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:n/a:n"),
            7.5)


class TestSeverityBands(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(cvss.severity(0.0), "None")
        self.assertEqual(cvss.severity(0.1), "Low")
        self.assertEqual(cvss.severity(3.9), "Low")
        self.assertEqual(cvss.severity(4.0), "Medium")
        self.assertEqual(cvss.severity(6.9), "Medium")
        self.assertEqual(cvss.severity(7.0), "High")
        self.assertEqual(cvss.severity(8.9), "High")
        self.assertEqual(cvss.severity(9.0), "Critical")
        self.assertEqual(cvss.severity(10.0), "Critical")


class TestRoundup(unittest.TestCase):
    def test_roundup_rounds_up_not_nearest(self):
        # 4.02 must become 4.1, not 4.0 (CVSS Roundup always rounds up).
        self.assertEqual(cvss._roundup(4.02), 4.1)
        # A value already at one decimal is left alone.
        self.assertEqual(cvss._roundup(4.0), 4.0)
        self.assertEqual(cvss._roundup(6.0), 6.0)


class TestBuildAndParse(unittest.TestCase):
    def test_build_vector_round_trip(self):
        components = {"AV": "N", "AC": "L", "PR": "n", "UI": "N",
                      "S": "U", "C": "h", "I": "N", "A": "N"}
        vector = cvss.build_vector(components)
        self.assertEqual(
            vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        # And it round-trips through the parser to the same score.
        self.assertEqual(cvss.base_score(cvss.parse_vector(vector)), 7.5)

    def test_format_vector_canonical_order(self):
        metrics = cvss.parse_vector(
            "C:H/AV:N/A:N/AC:L/I:N/PR:N/S:U/UI:N")  # scrambled order
        self.assertEqual(
            cvss.format_vector(metrics),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")


class TestParseErrors(unittest.TestCase):
    def test_invalid_metric_value(self):
        with self.assertRaises(cvss.CVSSError):
            cvss.parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")

    def test_unknown_metric(self):
        with self.assertRaises(cvss.CVSSError):
            cvss.parse_vector("CVSS:3.1/ZZ:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")

    def test_missing_metric(self):
        with self.assertRaises(cvss.CVSSError):
            cvss.parse_vector("CVSS:3.1/AV:N/AC:L")

    def test_empty(self):
        with self.assertRaises(cvss.CVSSError):
            cvss.parse_vector("")

    def test_build_rejects_missing(self):
        with self.assertRaises(cvss.CVSSError):
            cvss.build_vector({"AV": "N"})


if __name__ == "__main__":
    unittest.main()
