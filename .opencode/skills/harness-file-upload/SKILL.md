---
name: harness-file-upload
description: "Test file upload restrictions: extension bypass, MIME confusion, web shell, polyglot, path traversal via filename, and size/content-type validation."
---

# File upload — bypass, shell, polyglot

Source: `testing-file-upload`, `web-shell-upload`, `polyglot-files` (2024: .phar in PHP 8.3, SVG XSS, double extension on nginx, race condition upload→execute).

## Gate

Approved `host+upload endpoint` only. Every command via `cyber_process` `argv`. One mutation per upload. Upload only inert proof-of-concept files (text, benign image, canary callback). No destructive payload, no actual web shell that persists. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Baseline upload

Upload a legitimate file the application expects (e.g., profile.jpg). Record:
- Allowed extensions, MIME types, size limits
- Where the file lands (URL path, storage bucket, CDN)
- Whether the file is renamed, hashed, or stored as-is
- Response headers when the file is served back (Content-Type, Content-Disposition)

### 2. Extension bypass

One attempt per technique:
| Technique | Example | Server |
|---|---|---|
| Double extension | `shell.php.jpg` | Apache (AddHandler) |
| Null byte | `shell.php%00.jpg` | Legacy PHP/Java |
| Case variation | `shell.pHp`, `shell.PHP` | Windows IIS |
| Alternate extension | `.phtml`, `.phar`, `.php5`, `.shtml`, `.asp`, `.aspx`, `.jsp`, `.jspx` | Per stack |
| Trailing dot/space | `shell.php.`, `shell.php ` | Windows |
| Semicolon | `shell.asp;.jpg` | IIS |
| URL encoding | `shell%2Ephp` | Misconfigured proxy |

Record each probe as an observation with the server response.

### 3. MIME and Content-Type confusion

- Upload with correct extension but wrong Content-Type header
- Upload with wrong extension but correct Content-Type
- Upload with `application/octet-stream`
- Check if the server validates Content-Type, file magic bytes, or extension only

### 4. Content validation bypass

If the server validates file content:
| Validation | Bypass |
|---|---|
| Magic bytes check | Prepend valid magic bytes: `GIF89a;<?php` |
| Image dimension check | Valid image with PHP/JSP in EXIF comment |
| Polyglot | JPEG/PHP polyglot, PNG/JS polyglot, PDF/JS polyglot |
| SVG | `<svg><script>fetch('https://CALLBACK')</script></svg>` |
| ZIP/archive | Zip slip (`../../etc/passwd`), symlink in archive |

### 5. Filename injection

- Path traversal: `../../../etc/passwd`, `..%2F..%2F`
- Overwrite: upload with the name of an existing file (e.g., `index.html`)
- Special chars: `; sleep 5`, `$(id)`, `` `id` `` in filename (command injection)
- Long filename: >255 chars (buffer overflow in legacy handlers)
- Null in name: `file\x00.jpg`

### 6. Race condition (upload→execute)

If the server validates then deletes:
1. Upload a file that would be rejected
2. Send rapid GET requests to the uploaded path during the validation window
3. If the file is accessible before deletion, record as race condition

### 7. Execution verification

For any uploaded file that passes validation:
- Request the file directly via its URL
- Check Content-Type in response (is it `text/html`? `application/x-httpd-php`?)
- If the file contains a canary (`<?php echo "CANARY";`), check if the canary appears executed in the response
- For XSS via SVG/HTML: check if script executes (OOB callback)

### 8. Negative controls

- Control 1: legitimate file upload succeeds (positive control)
- Control 2: file with truly invalid content (random bytes, wrong magic) is rejected
- Control 3: bypass payload with a syntactically broken extension produces no execution

## Proof contract

A finding needs: (1) identified upload validation mechanism, (2) bypass that passes validation, (3) proof of execution or storage in exploitable location, (4) reproduction, (5) three negative controls. An uploaded file alone is a lead — execution or exploitable storage is a finding.

## Done

Each finding cites the validation bypass, the execution proof (served with executable Content-Type, or script executed), and the negative controls.
