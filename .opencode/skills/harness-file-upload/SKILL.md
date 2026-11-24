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
2. Use at most two locally coordinated approved requests during the validation window
3. If the file is accessible before deletion, record as race condition

### 7. Execution verification

For any uploaded file that passes validation:
- Request the file directly via its URL
- Check Content-Type in response (is it `text/html`? `application/x-httpd-php`?)
- Compare retrieved bytes with the full uploaded source. A literal `CANARY` inside
  `<?php echo "CANARY";` is not proof that PHP evaluated it. Require a distinct
  evaluated result plus a non-evaluating twin before claiming execution.
- For XSS via SVG/HTML: check if script executes (OOB callback)

### 8. Negative controls

- Control 1: legitimate file upload succeeds (positive control)
- Control 2: file with truly invalid content (random bytes, wrong magic) is rejected
- Control 3: bypass payload with a syntactically broken extension produces no execution

## Proof contract

A finding needs the validation mechanism, observed boundary violation, fresh reproduction,
legitimate positive control and actually executed rejecting/non-executing negative controls.
Storage alone is a lead unless a documented storage or isolation boundary is violated.

### Reproduction recipe

One file, one content-type, stored vs executed. Benign file control.

## Verification scenarios

Use unique inert files and synthetic storage paths; traversal targets stay in a disposable lab.
Bound upload-race checks to two approved requests, not an open-ended GET loop.
Content-Type suggests interpretation; it does not prove server-side execution.

```
cyber_process argv=["curl","-sS","-D","-","-F","file=@<fixture-file>;type=image/png","<approved-upload-url>"]
```

| Scenario | Evidence compared | Expected classification |
|---|---|---|
| Text is renamed to an executable extension but served as download | headers and retrieved bytes | no execution proof |
| Static source contains the literal canary string | full retrieved body | reflection, not evaluated output |
| Synthetic server-side canary evaluates to a distinct runtime marker | response and non-evaluating twin | bounded execution candidate |
| Other test user can retrieve a private upload | owner baseline and cross-user read | object isolation candidate |
| Oversized fixture is rejected at documented limit | size and rejection body | negative control |

Record filename, bytes hash, multipart metadata, stored id and retrieval origin separately.
Use sandboxed browser execution only for approved active-content cases.
Do not overwrite real index files or request real `/etc/passwd` as upload proof.
Track every uploaded test object through the mission's later approved cleanup.

### Executed local regression

`node test/opencode-skill-fixtures.cjs` executes the multipart curl recipe from
this file against a loopback service. It checks legitimate upload/read, cross-owner
disclosure on an intentionally leaky fixture, denial on its strict twin and bad magic.
A source file served unchanged as `application/x-httpd-php` is a false execution signal.
The fixture stores bytes in memory; it never interprets PHP or any uploaded code.
PHP/browser execution, archive extraction, traversal and race behavior remain unvalidated.

## Done

Each finding cites the actual validation/storage boundary or observed execution,
not executable Content-Type alone, plus positive and negative controls.
