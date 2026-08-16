"""finding-forge — turn a verified finding into a submission-ready report.

Public modules:
    cvss       Accurate CVSS v3.1 base-score math (parse / build / score).
    templates  Bug-class report scaffolds (HackerOne / Bugcrowd style).
    lint       Pre-submit gate: completeness + leaked-secret / PII checks.
    cli        argparse front end for the ``finding-forge`` command.
"""

__version__ = "1.0.0"
__author__ = "Jakub Kozub"
__license__ = "MIT"

__all__ = ["__version__", "cvss", "templates", "lint", "cli"]
