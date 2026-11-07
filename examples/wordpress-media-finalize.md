# Author can delete wp-config.php through the media finalize route, exposing the installer

## Summary

The media finalize route accepts a caller-controlled file name and resolves it without
constraining the result to the uploads directory. A user holding only `upload_files`, which
is the Author role, can therefore cause WordPress to delete an arbitrary path on disk,
including `wp-config.php`. A WordPress installation with no `wp-config.php` serves its
installer to any visitor, so deleting one file converts the lowest publishing role into full
control of the site and of the database credentials the installer is handed.

## Affected Asset

- Program / Target: WordPress
- URL / Endpoint: `POST /wp-json/wp/v2/media/<id>/finalize`
- Parameter / Component: the uploaded file name carried in the JSON body
- Environment: WordPress 7.0.3 with the bundled Gutenberg, tested 2026-10-17

## CVSS

- Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- Base score: **9.9 (Critical)**

Scope is Changed because the impact does not stop at the vulnerable component: removing
`wp-config.php` hands the installer, and with it the database, to an unauthenticated
visitor. Privileges Required is Low rather than None because the caller must hold
`upload_files`. Scored Unchanged the same impact is 8.8.

## Impact

An Author, the lowest role permitted to upload files, can:

1. delete any file the web server user can unlink, including files outside the document root;
2. delete `wp-config.php`, after which every page redirects to `/wp-admin/setup-config.php`
   and the installer answers 200 on a site that was already configured;
3. complete that installer against a database of their choosing, which yields administrator
   access to the site and renders the original installation unrecoverable without backups.

Step 2 is the part that makes this Critical rather than a file deletion bug. The measured
behaviour: on WordPress 7.0.3 `/wp-admin/setup-config.php` answers 409 while `wp-config.php`
exists, and with the file removed it answers 200.

## Steps to Reproduce

1. Create a user with the Author role and sign in as that user.
2. Begin a media upload so that an attachment id is issued and the editor nonce is printed
   to the page.
3. Call the finalize route for that attachment with a file name that traverses out of the
   uploads directory and names `wp-config.php`.
4. Observe HTTP 200 and the attachment finalized.
5. Request any page on the site. It now redirects to `/wp-admin/setup-config.php`, and that
   path answers 200.

Every request in this chain is authenticated, authorised and successful. The Author holds
`upload_files`, owns the attachment, and was given the nonce legitimately. Nothing 403s and
nothing is malformed, which is why no request signature distinguishes the attack.

## Proof of Concept

```http
POST /wp-json/wp/v2/media/<attachment-id>/finalize HTTP/1.1
Host: <target host>
Content-Type: application/json
X-WP-Nonce: <editor nonce printed to this Author>
Cookie: <Author session>

{"file_name": "<path traversing out of uploads>/wp-config.php"}
```

The traversal payload itself is withheld here; it is in the disclosed report. The point this
example is making is the shape of a finished report, not the exploit string.

## Remediation

Resolve the finalized path and require that the result is inside the uploads directory before
touching the filesystem, rather than validating the caller-supplied name. Deleting a file
should additionally require a capability appropriate to the file, not merely `upload_files`
on the attachment record.

Fixed in Gutenberg 23.8 and in WordPress core before 7.1 shipped.

## References

- HackerOne report 3931777: https://hackerone.com/reports/3931777
- Gutenberg pull request 81465: https://github.com/WordPress/gutenberg/pull/81465
- WordPress core changeset r63200: https://core.trac.wordpress.org/changeset/63200
- Write-up: https://jakubkozub.com/research/wordpress-media-finalize/
- Detections for this chain: https://github.com/kubakozub/detections
- OWASP Top 10 - A01:2021 Broken Access Control
- CWE-285: Improper Authorization
- CWE-862: Missing Authorization
