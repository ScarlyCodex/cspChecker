
**CSP Analyzer** is your go-to command-line tool for auditing Content Security Policies with a hacker’s flair. It scans your `.txt` CSP definitions, calls out dangerous directives, missing rules, and AWS-specific misconfigurations—all in color-coded, ☠️ hacker-style ☠️ console output, and can spit out a clean Markdown report.

---

## ⚙️ Features

- **Flag-driven interface**  
  • `-i <file>`: Specify CSP input file.  
  • `-o <file>`: Optional—save findings as a `README.md`-style Markdown report.

- **Colorized Console Output**  
  • 🟢 Success messages in cyan.  
  • 🔴 High-severity alerts in red.  
  • 🟡 Medium-severity alerts in yellow.

- **Hacker Banner**  
  • Compact ASCII header to set the tone.

- **Deep CSP Analysis**  
  • Detects missing **required directives** per AWS best practices.  
  • Flags **prohibited or obsolete directives**.  
  • Spots **dangerous values** (`'unsafe-inline'`, `'unsafe-eval'`, `*`, `'strict-dynamic'`).  
  • Catches **insecure HTTP resources** and **suspicious wildcards**.  
  • Verifies **AWS S3 domain usage** and **AWS Console connectivity** rules.

- **Markdown Report Generation**  
  • Auto-generates a tidy table of findings when using `-o`.  
  • Perfect for embedding in pentest reports or security docs.

---

## 🚀 Usage Example

```bash
# Analyze CSP and display in console only
$ go run csp_analyzer.go -i my-csp.txt

# Analyze CSP, display console output, and save report
$ go run csp_analyzer.go -i my-csp.txt -o csp-report.md
```

---

## 💥 Output Preview

```bash
╔════════════════════════════════╗
║        CSP ANALYZER v1.0       ║
╚════════════════════════════════╝
[!] Found 3 CSP issue(s):
[HIGH] Missing required directive according to AWS: script-src (Directive: script-src)
[MEDIUM] Suspicious wildcard: * (Directive: img-src)
[HIGH] Use of insecure HTTP resource (Directive: default-src)
```

---

Stay stealthy. Audit smart. Hack responsibly. 🖤🔍🛡️