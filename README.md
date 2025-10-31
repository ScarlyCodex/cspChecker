
CSP Analyzer is a CLI for auditing Content Security Policies with AWS Console best-practices in mind. It scans .txt CSP definitions, highlights dangerous directives and misconfigurations, and can emit a clean Markdown report.

---

## ⚙️ Features

- AWS-aware checks
  - Enforces required directives (e.g., `default-src`, `object-src` `'none'`, `style-src` 'unsafe-inline', `form-action`, `connect-src`, upgrade-insecure-requests).
	- Validates `connect-src` includes concrete console paths and (when you provide --console-path) the regional + region-less pair for home regions of the partitions you specify.
	- Enforces S3 bucket-less hosts only in `connect-src`, img-src, or `media-src`.

- Security rules that reduce false positives
	- Forbids `'self'`, `'unsafe-eval'`, and `'strict-dynamic'`.
	- Allows `'unsafe-inline'` only in `style-src` (required by Console Navigation).
	- Treats block-all-mixed-content as deprecated (warning/info), not a hard error; still requires upgrade-insecure-requests.
	- Accepts Lotus/Prism placeholders (e.g., .../lotus/csp/@...) as INFO, since TangerineBox resolves them at runtime.
	- Supports data:/blob: only in allowed directives (`font-src`, `img-src`, `media-src`, `child-src`, `worker-src`, `frame-src`, ``connect-src``).

- Domains, wildcards & 3P
	- First-party suffixes (like `.console.aws.amazon.com`, `.cdn.console.awsstatic.com`, `.api.aws`, `.amazonaws.com`, etc.) are recognized.
	- Safe wildcards (e.g., `*.console.api.aws`, `*.cdn.console.awsstatic.com`) are allowed; broad wildcards generate warnings.
	- Third-party hosts can be allow-listed via file (--allow3p).

- Severities for CI
	- Findings are tagged as ERROR, WARN, or INFO.
	-	`--fail-on-warn` makes the process exit non-zero if warnings exist.

- Report generation
  - Use `-o` to generate a tidy Markdown report (includes a raw JSON block inside a collapsible section).
---

## 🚩 Flags

- `-i` <file> — Input CSP text file (required).
- `-o` <file> — Optional Markdown report output.
- `--stack` tbox|orange|legacy — Console stack (default: tbox).
  - tbox: tolerant with placeholders (TangerineBox/Lotus/Prism).
  - legacy: strict; expects explicit console paths in connect-src.- 
`--console-path` /yourconsole/ — Path prefix your console “owns” (enables regional+region-less pair checks per partition).
- `--partitions` aws[,aws-cn,aws-us-gov,aws-iso,aws-isob] — Target partitions (default: aws).
- `--allow3p` <file> — File with allowed 3P patterns (lines like *.vendor.com or api.vendor.com).
- `--fail-on-warn` — Exit non-zero when warnings exist (great for CI).

---

## 🚀 Quick Start

```sh
# Minimal (unknown stack, default partition aws, stricter failures on warnings)
cspChecker -i my-csp.txt --fail-on-warn

# Stricter (treat unknown as legacy to require explicit console paths)
cspChecker -i my-csp.txt --stack legacy --fail-on-warn

# With console path to enable regional + region-less check for us-east-1 (aws partition)
cspChecker -i my-csp.txt --console-path /billing/ --partitions aws

# With third-party allowlist file
cspChecker -i my-csp.txt --allow3p preapproved.txt -o csp-report.md
```

Example `preapproved.txt`:
```ruby
*.trusted-analytics.example
payments.example
telemetry.vendor.net
```

📝 Example Input (copy/paste from Burp or DevTools):
```http
default-src 'none';
script-src https://prod.example.com;
style-src 'unsafe-inline' https://styles.example.com;
img-src https://images.example.com;
connect-src https://us-east-1.console.aws.amazon.com/miconsola/;
object-src 'none';
form-action https://forms.example.com;
frame-src https://frames.example.com;
font-src data: https://fonts.example.com;
media-src https://media.example.com;
upgrade-insecure-requests;
```

📤 Example Output (console)
```sh
╔════════════════════════════════╗
║        CSP ANALYZER v2         ║
╚════════════════════════════════╝
[!] Found 2 error(s) and 4 warning(s)

ERROR · Other checks:
- `default-src` default-src must not use 'self' or '*' (value: "*")

ERROR · Schemes / Protocols:
- `script-src` insecure protocol http:// (value: "http://cdn.bad.example")

WARN · Wildcards:
- `img-src` wildcard possibly over-broad; get AppSec approval (value: "https://*.images.example")

WARN · Deprecated directives:
- `block-all-mixed-content` block-all-mixed-content is deprecated; add upgrade-insecure-requests

INFO · Placeholders / Prism:
- `frame-src` placeholder accepted (value: "https://global.console.aws.amazon.com/lotus/csp/@amzn/aws-ccx-regions-availability/1")
```
---

Stay stealthy. Audit smart. Hack responsibly. 🖤🔍🛡️
