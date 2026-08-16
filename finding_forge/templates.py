"""Report scaffolds for common bug classes (HackerOne / Bugcrowd style).

Every template emits the same section skeleton triagers expect, pre-filled
with class-specific hints and a *suggested* CVSS vector (re-scored live).
Placeholders are written as ``<TODO: ...>`` so the linter can spot anything
left unfilled.  Keep example payloads redacted (``<token>`` etc.) so a fresh
scaffold never trips the secret checks.
"""

from __future__ import annotations

from . import cvss

# Order defines `--type` choices and README documentation order.
CLASS_ORDER = (
    "idor",
    "broken-access-control",
    "auth-bypass",
    "xss",
    "ssrf",
    "sqli",
    "csrf",
    "info-disclosure",
    "generic",
)

CLASSES = {
    "idor": {
        "name": "IDOR / Broken Object-Level Authorization",
        "title_hint": "IDOR in <endpoint> allows reading/modifying other users' <object>",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "summary": (
            "The `<TODO: endpoint>` endpoint authorizes the *session* but not "
            "*ownership* of the requested object. Any authenticated user can "
            "read `<TODO: describe object>` belonging to other users by "
            "changing the `<TODO: id parameter>` identifier."
        ),
        "impact": (
            "An authenticated attacker can enumerate `<TODO: id>` values and "
            "access `<TODO: what data/action>` across the whole user base "
            "without consent, exposing `<TODO: PII / financial / etc.>`."
        ),
        "steps": [
            "Authenticate as user A and capture a request to `<TODO: endpoint>`.",
            "Note the object identifier (e.g. `id=1001`) tied to user A.",
            "Replay the request changing the identifier to another user's value "
            "(e.g. `id=1002`).",
            "Observe the server returns user B's object with HTTP 200 instead of "
            "403/404.",
        ],
        "poc": (
            "```http\n"
            "GET /api/<TODO>/1002 HTTP/1.1\n"
            "Host: <TODO: target host>\n"
            "Cookie: <session cookie for user A>\n"
            "```\n"
            "Response returns user B's object (redact any real values before "
            "submitting)."
        ),
        "remediation": (
            "Enforce an object-level authorization check server-side: verify the "
            "authenticated principal owns (or is explicitly granted) the "
            "requested object before returning or mutating it. Prefer "
            "unguessable identifiers (UUIDv4) as defence-in-depth, not as the "
            "primary control."
        ),
        "references": [
            "OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization",
            "OWASP Top 10 - A01:2021 Broken Access Control",
            "CWE-639: Authorization Bypass Through User-Controlled Key",
        ],
    },
    "broken-access-control": {
        "name": "Broken Access Control / Privilege Escalation",
        "title_hint": "Missing authorization on <endpoint> allows <lower role> to <action>",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "summary": (
            "The `<TODO: endpoint/feature>` is reachable by users who lack the "
            "required role/permission. A `<TODO: low-privilege role>` can perform "
            "`<TODO: privileged action>` that must be restricted to "
            "`<TODO: intended role>`."
        ),
        "impact": (
            "A low-privileged (or unauthenticated) actor gains "
            "`<TODO: admin/other-tenant>` capabilities: `<TODO: read/modify/delete "
            "what>`. This breaks the application's trust boundary."
        ),
        "steps": [
            "Authenticate as a `<TODO: low-privilege role>` user.",
            "Send the request that the UI only exposes to `<TODO: privileged role>` "
            "(e.g. the admin-only endpoint below).",
            "Observe the action succeeds despite the caller lacking the role.",
        ],
        "poc": (
            "```http\n"
            "POST /admin/<TODO> HTTP/1.1\n"
            "Host: <TODO: target host>\n"
            "Authorization: Bearer <low-privilege token>\n"
            "\n"
            "<TODO: body>\n"
            "```"
        ),
        "remediation": (
            "Apply authorization at the server for every state-changing and "
            "sensitive-read endpoint (deny by default). Centralise the check; do "
            "not rely on hiding UI controls or on client-side role checks."
        ),
        "references": [
            "OWASP Top 10 - A01:2021 Broken Access Control",
            "CWE-285: Improper Authorization",
            "CWE-862: Missing Authorization",
        ],
    },
    "auth-bypass": {
        "name": "Authentication Bypass",
        "title_hint": "Authentication bypass on <asset> grants access without valid credentials",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "summary": (
            "`<TODO: asset/flow>` can be accessed without completing "
            "authentication. `<TODO: describe the flaw: forced browsing, weak "
            "token, logic flaw, default creds, JWT alg confusion, ...>`."
        ),
        "impact": (
            "An unauthenticated attacker obtains an authenticated session / "
            "access to `<TODO: protected resource>`, leading to "
            "`<TODO: account takeover / data access>`."
        ),
        "steps": [
            "From an unauthenticated context, request `<TODO: protected resource>`.",
            "Apply the bypass: `<TODO: e.g. tamper the token / skip the step / "
            "reuse a predictable value>`.",
            "Observe authenticated access is granted with no valid credentials.",
        ],
        "poc": (
            "```http\n"
            "GET /<TODO: protected path> HTTP/1.1\n"
            "Host: <TODO: target host>\n"
            "<TODO: tampered header/token demonstrating the bypass>\n"
            "```"
        ),
        "remediation": (
            "`<TODO: fix specific to the flaw>`. Validate tokens server-side "
            "(signature, algorithm allow-list, expiry, audience), enforce every "
            "step of the auth flow, and remove default/predictable credentials."
        ),
        "references": [
            "OWASP Top 10 - A07:2021 Identification and Authentication Failures",
            "CWE-287: Improper Authentication",
            "CWE-306: Missing Authentication for Critical Function",
        ],
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "title_hint": "Reflected/Stored XSS in <parameter> on <page>",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "summary": (
            "User input in `<TODO: parameter/field>` is reflected/stored into "
            "`<TODO: page/context>` without contextual output encoding, allowing "
            "arbitrary JavaScript execution in a victim's browser. Type: "
            "`<TODO: reflected | stored | DOM>`."
        ),
        "impact": (
            "Script runs in the victim's authenticated origin: session/token "
            "theft, request forgery on the victim's behalf, credential phishing, "
            "or defacement of `<TODO: scope>`."
        ),
        "steps": [
            "Navigate to `<TODO: URL>`.",
            "Set `<TODO: parameter>` to the payload below.",
            "Load the resulting page (for stored XSS: as a second victim user).",
            "Observe the injected script executes (the alert/DNS callback fires).",
        ],
        "poc": (
            "Proof payload (benign marker, no data exfiltration):\n"
            "```\n"
            "\"><img src=x onerror=alert(document.domain)>\n"
            "```\n"
            "Full URL: `https://<TODO: host>/<path>?<param>=%22%3E%3Cimg%20src%3Dx"
            "%20onerror%3Dalert(document.domain)%3E`"
        ),
        "remediation": (
            "Apply context-aware output encoding at every sink (HTML, attribute, "
            "JS, URL). Prefer a framework's auto-escaping, add a strict "
            "Content-Security-Policy as defence-in-depth, and set HttpOnly on "
            "session cookies."
        ),
        "references": [
            "OWASP Top 10 - A03:2021 Injection",
            "OWASP XSS Prevention Cheat Sheet",
            "CWE-79: Improper Neutralization of Input During Web Page Generation",
        ],
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "title_hint": "SSRF in <parameter> allows the server to reach internal/metadata endpoints",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
        "summary": (
            "`<TODO: parameter/feature>` fetches a user-supplied URL server-side "
            "without validating the destination, letting an attacker make the "
            "server issue requests to `<TODO: internal hosts / cloud metadata / "
            "localhost>`."
        ),
        "impact": (
            "Read internal-only services, cloud metadata credentials "
            "(e.g. 169.254.169.254), and pivot into the internal network. "
            "State the concrete internal resource reached: `<TODO>`."
        ),
        "steps": [
            "Locate the request that fetches a URL: `<TODO: endpoint/param>`.",
            "Point it at a collaborator/canary host you control and confirm the "
            "server calls out.",
            "Point it at an internal target (e.g. `http://169.254.169.254/...` or "
            "`http://127.0.0.1:<port>`).",
            "Capture the internal response returned/observable to the attacker.",
        ],
        "poc": (
            "```http\n"
            "POST /<TODO: endpoint> HTTP/1.1\n"
            "Host: <TODO: target host>\n"
            "Content-Type: application/json\n"
            "\n"
            "{\"url\": \"http://169.254.169.254/latest/meta-data/\"}\n"
            "```\n"
            "Include the out-of-band callback evidence (redact any credentials "
            "retrieved)."
        ),
        "remediation": (
            "Validate and allow-list destinations (scheme, host, port); resolve "
            "and re-check the IP after DNS to block link-local/private ranges and "
            "redirects; disable unused URL schemes; use IMDSv2 / metadata "
            "hardening. Do not rely on blocklists alone."
        ),
        "references": [
            "OWASP Top 10 - A10:2021 Server-Side Request Forgery",
            "OWASP SSRF Prevention Cheat Sheet",
            "CWE-918: Server-Side Request Forgery",
        ],
    },
    "sqli": {
        "name": "SQL Injection",
        "title_hint": "SQL injection in <parameter> on <endpoint>",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "summary": (
            "The `<TODO: parameter>` parameter on `<TODO: endpoint>` is "
            "concatenated into a SQL query without parameterization, allowing "
            "injection. Type: `<TODO: error-based | boolean-blind | time-blind | "
            "UNION>`."
        ),
        "impact": (
            "Read/modify arbitrary database contents (`<TODO: tables>`), "
            "authentication data, and potentially achieve code execution "
            "depending on DB privileges. Demonstrate with a harmless proof, not "
            "mass extraction."
        ),
        "steps": [
            "Send a baseline request to `<TODO: endpoint>` and record the response.",
            "Inject a boolean test in `<TODO: parameter>` (true vs false) and show "
            "the responses differ.",
            "Confirm with a time-based probe (e.g. a conditional sleep) to remove "
            "ambiguity.",
        ],
        "poc": (
            "Benign boolean proof (no data exfiltration):\n"
            "```\n"
            "<param>=1' AND '1'='1   -> normal response\n"
            "<param>=1' AND '1'='2   -> different/empty response\n"
            "```\n"
            "Time proof: `<param>=1'; <conditional sleep> -- ` delays the "
            "response by the injected interval."
        ),
        "remediation": (
            "Use parameterized queries / prepared statements everywhere; never "
            "build SQL by string concatenation. Apply least-privilege DB accounts "
            "and validate input types as defence-in-depth."
        ),
        "references": [
            "OWASP Top 10 - A03:2021 Injection",
            "OWASP SQL Injection Prevention Cheat Sheet",
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        ],
    },
    "csrf": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "title_hint": "CSRF on <action> lets an attacker perform it on a victim's behalf",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "summary": (
            "The state-changing action `<TODO: action/endpoint>` accepts requests "
            "without a valid anti-CSRF token (and cookies are sent cross-site), so "
            "a malicious page can force a logged-in victim to perform it."
        ),
        "impact": (
            "An attacker who lures a logged-in victim to a page can perform "
            "`<TODO: state change: change email, transfer, delete, ...>` as the "
            "victim, enabling `<TODO: account takeover / fraud>`."
        ),
        "steps": [
            "Log in as the victim in the browser.",
            "Host the HTML PoC below on an attacker origin and open it as the "
            "victim.",
            "Observe the action executes with the victim's session and no token.",
        ],
        "poc": (
            "```html\n"
            "<form action=\"https://<TODO: host>/<action>\" method=\"POST\">\n"
            "  <input type=\"hidden\" name=\"<TODO: field>\" value=\"<TODO: value>\">\n"
            "</form>\n"
            "<script>document.forms[0].submit()</script>\n"
            "```"
        ),
        "remediation": (
            "Require an unpredictable, per-session anti-CSRF token on every "
            "state-changing request and verify it server-side; set "
            "`SameSite=Lax/Strict` on session cookies; for APIs, require a custom "
            "header or re-authentication."
        ),
        "references": [
            "OWASP CSRF Prevention Cheat Sheet",
            "OWASP Top 10 - A01:2021 Broken Access Control",
            "CWE-352: Cross-Site Request Forgery",
        ],
    },
    "info-disclosure": {
        "name": "Sensitive Information Disclosure",
        "title_hint": "Sensitive information disclosure via <endpoint/artifact>",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "summary": (
            "`<TODO: endpoint/file/response>` exposes sensitive data "
            "(`<TODO: secrets / PII / internal details>`) to an actor who should "
            "not have access."
        ),
        "impact": (
            "Disclosure of `<TODO: what>` enables `<TODO: follow-on attack: "
            "credential reuse, targeted phishing, further compromise>`. Quantify "
            "scope: `<TODO: how many records / which secrets>`."
        ),
        "steps": [
            "Request `<TODO: endpoint/artifact>` (state the required privilege, if "
            "any).",
            "Observe the sensitive fields in the response/artifact.",
            "Note exactly which sensitive values are exposed (redact them here).",
        ],
        "poc": (
            "```http\n"
            "GET /<TODO: path> HTTP/1.1\n"
            "Host: <TODO: target host>\n"
            "```\n"
            "Response contains `<TODO: field names>` — redact the actual secret "
            "values in the report and reference them by placeholder."
        ),
        "remediation": (
            "Remove sensitive data from the exposed surface; enforce "
            "authorization on it; rotate any leaked secrets; strip verbose "
            "errors, debug endpoints, and stack traces from production."
        ),
        "references": [
            "OWASP Top 10 - A01:2021 Broken Access Control",
            "OWASP Top 10 - A05:2021 Security Misconfiguration",
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        ],
    },
    "generic": {
        "name": "Security Vulnerability (generic)",
        "title_hint": "<Vulnerability class> in <asset>",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "summary": (
            "`<TODO: one or two sentences — what the flaw is, where it lives, and "
            "the security property it breaks>`."
        ),
        "impact": (
            "`<TODO: what an attacker gains, under what preconditions, and why it "
            "matters to the business>`."
        ),
        "steps": [
            "`<TODO: precondition / setup>`",
            "`<TODO: the action that triggers the issue>`",
            "`<TODO: the observable, attacker-relevant result>`",
        ],
        "poc": (
            "`<TODO: exact request/response, script, or screenshot reference "
            "proving the issue — keep it minimal and reproducible; redact "
            "secrets>`"
        ),
        "remediation": (
            "`<TODO: the specific, actionable fix and any defence-in-depth>`."
        ),
        "references": [
            "`<TODO: CWE-___ and any relevant OWASP / vendor references>`",
        ],
    },
}


def _render_section(title, body):
    return "## %s\n\n%s\n" % (title, body)


def render(bug_type, title=None):
    """Return a complete Markdown report scaffold for ``bug_type``.

    Raises :class:`KeyError` for an unknown class.
    """
    if bug_type not in CLASSES:
        raise KeyError(bug_type)
    spec = CLASSES[bug_type]

    vector = spec["cvss"]
    score, rating, _ = cvss.score_vector(vector)
    heading = title or spec["title_hint"]

    steps = "\n".join(
        "%d. %s" % (i + 1, s) for i, s in enumerate(spec["steps"])
    )
    references = "\n".join("- %s" % r for r in spec["references"])

    cvss_body = (
        "- Vector: `%s`\n"
        "- Base score: **%.1f (%s)**\n\n"
        "> Suggested starting vector for a typical %s. Re-score for YOUR exact\n"
        "> impact: `finding-forge cvss \"<your vector>\"`."
    ) % (vector, score, rating, spec["name"])

    parts = [
        "# %s" % heading,
        "",
        "> Bug class: **%s** — DRAFT. Fill every `<TODO: ...>`, redact real"
        " secrets, and delete this banner before submitting." % spec["name"],
        "",
        _render_section("Summary", spec["summary"]),
        _render_section(
            "Affected Asset",
            "- Program / Target: <TODO: program or company>\n"
            "- URL / Endpoint: <TODO: https://...>\n"
            "- Parameter / Component: <TODO: e.g. `id` path parameter>\n"
            "- Environment: <TODO: production | staging> (tested <TODO: date>)",
        ),
        _render_section("CVSS", cvss_body),
        _render_section("Impact", spec["impact"]),
        _render_section("Steps to Reproduce", steps),
        _render_section("Proof of Concept", spec["poc"]),
        _render_section("Remediation", spec["remediation"]),
        _render_section("References", references),
    ]
    return "\n".join(parts).rstrip() + "\n"
