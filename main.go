package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Severity string

const (
	SeverityError Severity = "ERROR"
	SeverityWarn  Severity = "WARN"
	SeverityInfo  Severity = "INFO"
)

type CSPIssue struct {
	Severity  Severity
	Message   string
	Directive string
	Value     string
}

type IssueGroup struct {
	Title   string
	Details []string
}

type Config struct {
	Env           string   // fixed to "prod"
	Stack         string   // tbox | orange | legacy
	ConsolePath   string   // e.g. /myconsole/
	Partitions    []string // e.g. aws,aws-cn,aws-us-gov,aws-iso,aws-isob
	Allow3P       []string // extra allow-list patterns (wildcards / suffixes)
	Allow127      bool     // optional override to allow 127.0.0.1 even in prod
	FailOnWarning bool
}

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
)

// ---- main ----

func main() {
	inputFile := flag.String("i", "", "Path to CSP input file")
	outputFile := flag.String("o", "", "Path to save report (Markdown)")
	stack := flag.String("stack", "tbox", "Console stack: tbox|orange|legacy")
	consolePath := flag.String("console-path", "", "Console path prefix (e.g., /myconsole/)")
	partitions := flag.String("partitions", "aws", "Comma-separated partitions: aws,aws-cn,aws-us-gov,aws-iso,aws-isob")
	allow3pPath := flag.String("allow3p", "", "Path to file with extra allowed 3P domains/patterns (one per line)")
	allow127 := flag.Bool("allow-127", false, "Allow 127.0.0.1 even in prod (use sparingly)")
	failWarn := flag.Bool("fail-on-warn", false, "Return non-zero exit if WARN present")

	flag.Parse()
	if *inputFile == "" {
		fmt.Println("Usage: ./cspChecker -i <input-csp.txt> [-o <output.md>] [--stack tbox|orange|legacy] [--console-path /myconsole/] [--partitions aws,aws-cn] [--allow3p allow.txt] [--allow-127] [--fail-on-warn]")
		os.Exit(1)
	}

	content, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	cfg := Config{
		Env:           "prod", // always assume prod
		Stack:         strings.ToLower(*stack),
		ConsolePath:   normalizedConsolePath(*consolePath),
		Partitions:    splitCSV(*partitions),
		Allow3P:       loadAllow3P(*allow3pPath),
		Allow127:      *allow127,
		FailOnWarning: *failWarn,
	}

	printBanner()
	directives := parseCSP(string(content))
	issues := analyzeCSP(directives, cfg)

	errors, warns := countBySeverity(issues)
	switch {
	case errors == 0 && warns == 0:
		printSuccess("No CSP issues found")
	case errors == 0 && warns > 0:
		printWarn(fmt.Sprintf("Found %d warning(s)", warns))
	default:
		printError(fmt.Sprintf("Found %d error(s) and %d warning(s)", errors, warns))
	}
	printFormattedIssues(issues)

	if *outputFile != "" {
		if err := saveReport(*outputFile, issues); err != nil {
			fmt.Printf("Error saving report: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Report saved to %s\n", *outputFile)
	}

	if errors > 0 || (cfg.FailOnWarning && warns > 0) {
		os.Exit(2)
	}
}

// ---- helpers: UI ----

func printBanner() {
	fmt.Println(colorCyan + "╔════════════════════════════════╗")
	fmt.Println("║        CSP ANALYZER v2         ║")
	fmt.Println("╚════════════════════════════════╝" + colorReset)
}
func printSuccess(msg string) { fmt.Println(colorGreen + "[✓] " + msg + colorReset) }
func printError(msg string)   { fmt.Println(colorRed + "[!] " + msg + colorReset) }
func printWarn(msg string)    { fmt.Println(colorYellow + "[~] " + msg + colorReset) }

func printFormattedIssues(issues []CSPIssue) {
	if len(issues) == 0 {
		return
	}
	groups := groupIssues(issues)
	for i, g := range groups {
		fmt.Printf("%s%d. %s:%s\n", colorCyan, i+1, g.Title, colorReset)
		for _, d := range g.Details {
			fmt.Printf("%s- %s%s\n", colorYellow, d, colorReset)
		}
		fmt.Println()
	}
}

func saveReport(filename string, issues []CSPIssue) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	if len(issues) == 0 {
		fmt.Fprintln(f, "No CSP issues found.")
		return nil
	}
	// also include a JSON block with raw issues
	fmt.Fprintln(f, "## Issues")
	groups := groupIssues(issues)
	for i, g := range groups {
		fmt.Fprintf(f, "%d. %s:\n", i+1, g.Title)
		for _, d := range g.Details {
			fmt.Fprintf(f, "- %s\n", d)
		}
		fmt.Fprintln(f)
	}
	raw, _ := json.MarshalIndent(issues, "", "  ")
	fmt.Fprintf(f, "\n<details><summary>Raw</summary>\n\n```json\n%s\n```\n\n</details>\n", string(raw))
	return nil
}

func groupIssues(issues []CSPIssue) []IssueGroup {
	m := map[string]*IssueGroup{}
	for _, is := range issues {
		title := string(is.Severity) + " · " + pickGroupTitle(is)
		line := fmt.Sprintf("`%s` %s%s", is.Directive, is.Message, ifVal(is.Value))
		if g, ok := m[title]; ok {
			g.Details = append(g.Details, line)
		} else {
			m[title] = &IssueGroup{Title: title, Details: []string{line}}
		}
	}
	out := make([]IssueGroup, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out
}

func ifVal(v string) string {
	if v == "" {
		return ""
	}
	return fmt.Sprintf(" (value: %q)", v)
}

func countBySeverity(issues []CSPIssue) (int, int) {
	errs := 0
	warns := 0
	for _, i := range issues {
		if i.Severity == SeverityError {
			errs++
		} else if i.Severity == SeverityWarn {
			warns++
		}
	}
	return errs, warns
}

func pickGroupTitle(i CSPIssue) string {
	switch {
	case strings.Contains(i.Message, "'self'"):
		return "Use of 'self'"
	case strings.Contains(i.Message, "unsafe-"):
		return "Unsafe directives"
	case strings.Contains(i.Message, "S3"):
		return "S3 rules"
	case strings.Contains(i.Message, "home region"):
		return "Home regions / Partitions"
	case strings.Contains(i.Message, "placeholder"):
		return "Placeholders / Prism"
	case strings.Contains(i.Message, "wildcard"):
		return "Wildcards"
	case strings.Contains(i.Message, "deprecated"):
		return "Deprecated directives"
	case strings.Contains(i.Message, "schema") || strings.Contains(i.Message, "protocol"):
		return "Schemes / Protocols"
	case strings.Contains(i.Message, "URL") || strings.Contains(i.Message, "path"):
		return "URL / Path patterns"
	default:
		return "Other checks"
	}
}

// ---- parser & normalization ----

func parseCSP(csp string) map[string][]string {
	out := map[string][]string{}
	csp = strings.TrimSpace(strings.TrimPrefix(csp, "Content-Security-Policy:"))
	parts := strings.Split(csp, ";")
	for _, p := range parts {
		sec := strings.TrimSpace(p)
		if sec == "" {
			continue
		}
		toks := strings.Fields(sec)
		if len(toks) == 0 {
			continue
		}
		dir := strings.ToLower(toks[0])
		vals := []string{}
		for _, v := range toks[1:] {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			vals = append(vals, trimTrailingSlash(v))
		}
		out[dir] = vals
	}
	return out
}

func trimTrailingSlash(s string) string {
	if strings.HasPrefix(s, "http") || strings.HasPrefix(s, "wss") {
		return strings.TrimRight(s, "/")
	}
	return s
}

func normalizedConsolePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, t := range strings.Split(s, ",") {
		out = append(out, strings.TrimSpace(t))
	}
	return out
}

func loadAllow3P(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		printWarn("Could not open allow3p file: " + err.Error())
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// ---- Analyzer ----

func analyzeCSP(directives map[string][]string, cfg Config) []CSPIssue {
	var issues []CSPIssue

	// 1) Base requirements
	checkRequiredDirectives(directives, &issues)
	checkObjectSrcNone(directives, &issues)
	checkUpgradeInsecureRequests(directives, &issues)

	// 2) Dangerous / prohibited values
	checkSelfDirective(directives, &issues)
	checkUnsafeValues(directives, &issues)
	checkBlockAllMixedContent(directives, &issues)

	// 3) style-src 'unsafe-inline' only there (and required)
	checkStyleSrcInline(directives, &issues)

	// 4) Schemes/127.0.0.1/data/blob
	checkSchemesAndDataBlob(directives, cfg, &issues)

	// 5) S3 bucket-less / allowed directives
	verifyS3Domains(directives, &issues)

	// 6) connect-src: concrete console paths + home regions pairs
	checkConnectSrcPaths(directives, cfg, &issues)

	// 7) Allowed domains, wildcards, and 3P
	checkAllowedDomainsAndWildcards(directives, cfg, &issues)

	// 8) Duplicates / empty
	checkDuplicateValues(directives, &issues)
	checkEmptyValues(directives, &issues)

	return issues
}

// ---- Rule checks ----

func checkRequiredDirectives(d map[string][]string, issues *[]CSPIssue) {
	required := []string{"default-src", "style-src", "connect-src", "object-src", "form-action"}
	for _, r := range required {
		if _, ok := d[r]; !ok {
			*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "missing required directive", Directive: r})
		}
	}
	// default-src must be 'none' or console CDN
	if vals, ok := d["default-src"]; ok {
		if len(vals) == 0 {
			*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "default-src with no values", Directive: "default-src"})
		} else {
			okVal := false
			for _, v := range vals {
				if v == "'none'" || strings.Contains(v, ".cdn.console.awsstatic.com") {
					okVal = true
				}
				if v == "'self'" || v == "*" {
					*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "default-src must not use 'self' or '*'", Directive: "default-src", Value: v})
				}
			}
			if !okVal {
				*issues = append(*issues, CSPIssue{Severity: SeverityWarn, Message: "prefer 'none' or your console CDN domain in default-src", Directive: "default-src"})
			}
		}
	}
}

func checkObjectSrcNone(d map[string][]string, issues *[]CSPIssue) {
	vals, ok := d["object-src"]
	if !ok {
		return
	}
	if len(vals) != 1 || vals[0] != "'none'" {
		*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "object-src must be exactly 'none'", Directive: "object-src", Value: strings.Join(vals, " ")})
	}
}

func checkUpgradeInsecureRequests(d map[string][]string, issues *[]CSPIssue) {
	if _, ok := d["upgrade-insecure-requests"]; !ok {
		*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "missing 'upgrade-insecure-requests'", Directive: "upgrade-insecure-requests"})
	}
}

func checkSelfDirective(d map[string][]string, issues *[]CSPIssue) {
	for dir, vals := range d {
		if contains(vals, "'self'") {
			*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "use of 'self' breaks console isolation", Directive: dir})
		}
	}
}

func checkUnsafeValues(d map[string][]string, issues *[]CSPIssue) {
	for dir, vals := range d {
		for _, v := range vals {
			switch v {
			case "'unsafe-eval'":
				*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "use of dangerous value 'unsafe-eval'", Directive: dir})
			case "'strict-dynamic'":
				*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "use of dangerous value 'strict-dynamic'", Directive: dir})
			}
		}
		// script-src must NOT include data: or blob:
		if dir == "script-src" {
			for _, v := range vals {
				if strings.HasPrefix(v, "data:") || strings.HasPrefix(v, "blob:") {
					*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "script-src must not allow data: or blob:", Directive: dir, Value: v})
				}
			}
		}
	}
}

func checkBlockAllMixedContent(d map[string][]string, issues *[]CSPIssue) {
	if _, ok := d["block-all-mixed-content"]; ok {
		if _, hasUIR := d["upgrade-insecure-requests"]; !hasUIR {
			*issues = append(*issues, CSPIssue{Severity: SeverityWarn, Message: "block-all-mixed-content is deprecated; add upgrade-insecure-requests", Directive: "block-all-mixed-content"})
		} else {
			*issues = append(*issues, CSPIssue{Severity: SeverityInfo, Message: "block-all-mixed-content is deprecated (kept for compatibility)", Directive: "block-all-mixed-content"})
		}
	}
	if _, ok := d["plugin-types"]; ok {
		*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "prohibited directive", Directive: "plugin-types"})
	}
}

func checkStyleSrcInline(d map[string][]string, issues *[]CSPIssue) {
	vals, ok := d["style-src"]
	if !ok || !contains(vals, "'unsafe-inline'") {
		*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "style-src must include 'unsafe-inline' for Console Navigation", Directive: "style-src"})
	}
	for dir, v := range d {
		if dir == "style-src" {
			continue
		}
		if contains(v, "'unsafe-inline'") {
			*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "'unsafe-inline' is allowed only in style-src", Directive: dir})
		}
	}
}

func checkSchemesAndDataBlob(d map[string][]string, cfg Config, issues *[]CSPIssue) {
	for dir, vals := range d {
		for _, v := range vals {
			if isKeyword(v) || strings.HasPrefix(v, "'nonce-") {
				continue
			}
			if strings.HasPrefix(v, "data:") || strings.HasPrefix(v, "blob:") {
				if !allowedDataBlobDir(dir) {
					*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "data:/blob: not allowed for this directive", Directive: dir, Value: v})
				}
				continue
			}
			if strings.HasPrefix(v, "http://") {
				*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "insecure protocol http://", Directive: dir, Value: v})
				continue
			}
			if !(strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "wss://")) {
				// 127.0.0.1 only if explicitly allowed (even in prod)
				if (strings.HasPrefix(v, "http://127.0.0.1") || strings.HasPrefix(v, "https://127.0.0.1")) && cfg.Allow127 {
					continue
				}
				*issues = append(*issues, CSPIssue{Severity: SeverityWarn, Message: "unknown or unsupported scheme", Directive: dir, Value: v})
			}
		}
	}
}

func verifyS3Domains(d map[string][]string, issues *[]CSPIssue) {
	allowed := map[string]bool{"connect-src": true, "img-src": true, "media-src": true}
	s3Host := regexp.MustCompile(`(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$`)
	for dir, vals := range d {
		for _, v := range vals {
			u, err := url.Parse(strings.ReplaceAll(v, "*", "wildcard"))
			if err != nil || u.Host == "" {
				continue
			}
			if s3Host.MatchString(u.Host) {
				if !allowed[dir] {
					*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "S3 bucket-less allowed only in connect-src/img-src/media-src", Directive: dir, Value: v})
				}
			}
		}
	}
}

func checkConnectSrcPaths(d map[string][]string, cfg Config, issues *[]CSPIssue) {
	vals, ok := d["connect-src"]
	if !ok {
		return
	}
	// must include console paths (unless TBox injects placeholders at runtime; we still prefer to see them)
	hasConsole := false
	for _, v := range vals {
		if strings.Contains(v, ".console.aws.amazon.com/") || strings.HasPrefix(v, "https://console.aws.amazon.com/") {
			hasConsole = true
			break
		}
	}
	if !hasConsole && cfg.Stack != "tbox" {
		*issues = append(*issues, CSPIssue{Severity: SeverityError, Message: "connect-src must include AWS console paths", Directive: "connect-src"})
	}

	// require regional + region-less pair for each partition home region if consolePath is provided
	if cfg.ConsolePath != "" {
		home := map[string]string{
			"aws":        "us-east-1",
			"aws-cn":     "cn-north-1",
			"aws-us-gov": "us-gov-west-1",
			"aws-iso":    "us-iso-east-1",
			"aws-isob":   "us-isob-east-1",
		}
		for _, part := range cfg.Partitions {
			hr, ok := home[part]
			if !ok {
				continue
			}
			regional := fmt.Sprintf("https://%s.console.aws.amazon.com%s", hr, cfg.ConsolePath)
			regionless := fmt.Sprintf("https://console.aws.amazon.com%s", cfg.ConsolePath)
			if !contains(vals, strings.TrimRight(regional, "/")) || !contains(vals, strings.TrimRight(regionless, "/")) {
				*issues = append(*issues, CSPIssue{
					Severity:  SeverityError,
					Message:   fmt.Sprintf("connect-src must include regional and region-less for home region %s (partition %s)", hr, part),
					Directive: "connect-src",
					Value:     "missing regional/regionless pair for console path",
				})
			}
		}
	}
}

func checkAllowedDomainsAndWildcards(d map[string][]string, cfg Config, issues *[]CSPIssue) {
	alwaysOKSuffix := []string{
		".amazonaws.com",
		".aws.amazon.com",
		".awsstatic.com",
		".cloudfront.net",
		".console.aws",
		".api.aws",
		".a2z.com",
		".aws.dev",
		".console.aws.amazon.com",
		".signin.aws.amazon.com",
		".cdn.console.awsstatic.com",
		".ccs.amazonaws.com",
	}
	validWildcardExact := map[string]bool{
		"*.cdn.console.awsstatic.com": true,
		"*.console.aws.amazon.com":    true, // require concrete path
		"*.signin.aws.amazon.com":     true,
		"*.ccs.amazonaws.com":         true,
		"*.console.api.aws":           true,
		"*.api.aws":                   true,
	}

	placeholder := regexp.MustCompile(`(@[A-Za-z0-9_\-]+|(\$\{[^}]+\})|(\{\{[^}]+\}\}))`)

	for dir, vals := range d {
		for _, v := range vals {
			if isKeyword(v) || strings.HasPrefix(v, "'nonce-") {
				continue
			}
			if strings.HasPrefix(v, "data:") || strings.HasPrefix(v, "blob:") {
				continue
			}
			// placeholders allowed
			if placeholder.MatchString(v) || strings.Contains(v, "/lotus/csp/@") {
				*issues = append(*issues, CSPIssue{Severity: SeverityInfo, Message: "placeholder accepted", Directive: dir, Value: v})
				continue
			}

			if !(strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "wss://")) {
				continue
			}

			u, err := url.Parse(v)
			if err != nil || u.Host == "" {
				*issues = append(*issues, CSPIssue{Severity: SeverityWarn, Message: "invalid URL", Directive: dir, Value: v})
				continue
			}

			host := u.Host
			// explicit wildcards
			if strings.HasPrefix(host, "*.") {
				if validWildcardExact[host] {
					// if *.console.aws.amazon.com, require a concrete path
					if strings.Contains(host, ".console.aws.amazon.com") && (u.Path == "" || u.Path == "/") {
						*issues = append(*issues, CSPIssue{Severity: SeverityWarn, Message: "wildcard requires a concrete path (avoid broad console wildcard)", Directive: dir, Value: v})
					}
					continue
				}
				// allow3p exception
				if matchesAny(host, cfg.Allow3P) {
					*issues = append(*issues, CSPIssue{Severity: SeverityInfo, Message: "wildcard allowed by external allowlist", Directive: dir, Value: v})
					continue
				}
				*issues = append(*issues, CSPIssue{Severity: SeverityWarn, Message: "wildcard possibly over-broad; get AppSec approval", Directive: dir, Value: v})
				continue
			}

			// first-party suffixes
			if hasSuffixAny(host, alwaysOKSuffix) {
				continue
			}

			// third-party requires approval (allow list file)
			if matchesAny(host, cfg.Allow3P) {
				*issues = append(*issues, CSPIssue{Severity: SeverityInfo, Message: "3P domain allowed by external allowlist", Directive: dir, Value: v})
				continue
			}
			*issues = append(*issues, CSPIssue{Severity: SeverityWarn, Message: "3P domain requires AppSec approval", Directive: dir, Value: v})
		}
	}
}

// NEW: missing helper added
func checkDuplicateValues(d map[string][]string, issues *[]CSPIssue) {
	for dir, vals := range d {
		seen := map[string]bool{}
		for _, v := range vals {
			key := strings.ToLower(v)
			if seen[key] {
				*issues = append(*issues, CSPIssue{Severity: SeverityInfo, Message: "duplicate value", Directive: dir, Value: v})
			}
			seen[key] = true
		}
	}
}

// NEW: missing helper added
func checkEmptyValues(d map[string][]string, issues *[]CSPIssue) {
	for dir, vals := range d {
		if dir == "upgrade-insecure-requests" {
			continue
		}
		if len(vals) == 0 {
			*issues = append(*issues, CSPIssue{Severity: SeverityWarn, Message: "directive without values", Directive: dir})
		}
	}
}

// ---- tiny utils ----

func contains(sl []string, s string) bool {
	for _, v := range sl {
		if v == s {
			return true
		}
	}
	return false
}

func isKeyword(v string) bool {
	switch v {
	case "'none'", "'self'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'":
		return true
	default:
		return false
	}
}

func allowedDataBlobDir(dir string) bool {
	switch dir {
	case "font-src", "img-src", "media-src", "child-src", "worker-src", "frame-src", "connect-src":
		return true
	default:
		return false
	}
}

func hasSuffixAny(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

func matchesAny(host string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, strings.TrimPrefix(p, "*")) {
				return true
			}
		} else if strings.EqualFold(host, p) || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}