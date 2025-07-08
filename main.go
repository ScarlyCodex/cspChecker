package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type CSPIssue struct {
	Severity  string
	Message   string
	Directive string
}

// ANSI color codes for console styling
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

func main() {
	inputFile := flag.String("i", "", "Path to CSP input file")
	outputFile := flag.String("o", "", "Path to save report (Markdown format)")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Usage: go run csp_analyzer.go -i <input-csp.txt> [-o <output.md>]")
		os.Exit(1)
	}

	content, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	issues := analyzeCSP(string(content))
	printBanner()

	if len(issues) == 0 {
		printSuccess("No CSP issues found")
	} else {
		printError(fmt.Sprintf("Found %d CSP issue(s):", len(issues)))
		for _, issue := range issues {
			printIssue(issue)
		}
	}

	if *outputFile != "" {
		err = saveReport(*outputFile, issues)
		if err != nil {
			fmt.Printf("Error saving report: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Report saved to %s\n", *outputFile)
	}
}

// printBanner displays a compact CSP Analyzer header
func printBanner() {
	fmt.Println(colorCyan + "╔════════════════════════════════╗")
	fmt.Println("║        CSP ANALYZER v1.0       ║")
	fmt.Println("╚════════════════════════════════╝" + colorReset)
}

func printSuccess(msg string) {
	fmt.Println(colorCyan + "[✓] " + msg + colorReset)
}

func printError(msg string) {
	fmt.Println(colorRed + "[!] " + msg + colorReset)
}

func printIssue(issue CSPIssue) {
	var color string
	switch issue.Severity {
	case "HIGH":
		color = colorRed
	case "MEDIUM":
		color = colorYellow
	default:
		color = colorCyan
	}
	fmt.Printf("%s[%s] %s (Directive: %s)%s\n", color, issue.Severity, issue.Message, issue.Directive, colorReset)
}

// saveReport writes a Markdown table of issues to the specified file
func saveReport(filename string, issues []CSPIssue) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, "# CSP Issues Report")
	if len(issues) == 0 {
		fmt.Fprintln(file, "\nNo CSP issues found.")
		return nil
	}

	fmt.Fprintln(file, "\n| Severity | Message | Directive |")
	fmt.Fprintln(file, "|---|---|---|")
	for _, issue := range issues {
		fmt.Fprintf(file, "| %s | %s | %s |\n", issue.Severity, issue.Message, issue.Directive)
	}
	return nil
}

// analyzeCSP parses and evaluates a CSP string, returning any issues found
func analyzeCSP(csp string) []CSPIssue {
	var issues []CSPIssue
	directives := parseCSP(csp)

	dangerousValues := []string{"'unsafe-inline'", "'unsafe-eval'", "*", "'strict-dynamic'"}
	requiredDirectives := []string{
		"default-src", "script-src", "style-src", "connect-src",
		"object-src", "form-action", "base-uri", "frame-ancestors",
	}
	prohibitedDirectives := []string{"plugin-types"}

	// 1. Check required directives
	for _, dir := range requiredDirectives {
		if _, ok := directives[dir]; !ok {
			issues = append(issues, CSPIssue{"HIGH", fmt.Sprintf("Missing required directive according to AWS: %s", dir), dir})
		}
	}

	// 2. Check prohibited directives
	for _, dir := range prohibitedDirectives {
		if _, ok := directives[dir]; ok {
			issues = append(issues, CSPIssue{"MEDIUM", fmt.Sprintf("Obsolete/prohibited directive according to AWS: %s", dir), dir})
		}
	}

	// 3. Evaluate each directive’s values
	for dir, values := range directives {
		if len(values) == 0 && dir != "upgrade-insecure-requests" {
			issues = append(issues, CSPIssue{"HIGH", "Directive without defined values", dir})
			continue
		}

		for _, val := range values {
			if strings.HasPrefix(val, "http:") {
				issues = append(issues, CSPIssue{"HIGH", "Use of insecure HTTP resource", dir})
			}
			for _, danger := range dangerousValues {
				if val == danger {
					issues = append(issues, CSPIssue{"HIGH", fmt.Sprintf("Use of dangerous value: %s", val), dir})
				}
			}
			if strings.Contains(val, "*") && !isValidWildcard(val) {
				issues = append(issues, CSPIssue{"MEDIUM", fmt.Sprintf("Suspicious wildcard: %s", val), dir})
			}
			if val == "'unsafe-inline'" && dir != "style-src" {
				issues = append(issues, CSPIssue{"HIGH", "'unsafe-inline' should only be used in style-src (prefer nonce/hash)", dir})
			}
		}
	}

	// 4. AWS-specific rules
	if values, ok := directives["default-src"]; ok {
		if !contains(values, "'none'") && !isValidCDNDomain(values) {
			issues = append(issues, CSPIssue{"MEDIUM", "default-src does not contain 'none' or valid CDN domain", "default-src"})
		}
	}

	if values, ok := directives["object-src"]; ok {
		if !(len(values) == 1 && values[0] == "'none'") {
			issues = append(issues, CSPIssue{"HIGH", "object-src should be only 'none'", "object-src"})
		}
	}

	verifyS3Domains(directives, &issues)
	verifyAWSConsole(directives, &issues)

	return issues
}

// parseCSP splits the CSP string into directives and their values
func parseCSP(csp string) map[string][]string {
	directives := make(map[string][]string)
	for _, section := range strings.Split(csp, ";") {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}
		parts := strings.Fields(section)
		if len(parts) > 0 {
			directives[parts[0]] = parts[1:]
		}
	}
	return directives
}

// verifyS3Domains flags S3 usage outside allowed directives
func verifyS3Domains(directives map[string][]string, issues *[]CSPIssue) {
	allowed := map[string]bool{
		"connect-src": true,
		"img-src":     true,
		"media-src":   true,
	}
	s3Pattern := regexp.MustCompile(`^https://[a-z0-9-]+\.s3\.amazonaws\.com/?`)
	for dir, values := range directives {
		for _, val := range values {
			if s3Pattern.MatchString(val) && !allowed[dir] {
				*issues = append(*issues, CSPIssue{"HIGH", "Using S3 in directive not allowed by AWS", dir})
			}
		}
	}
}

// verifyAWSConsole ensures connect-src includes AWS console endpoints
func verifyAWSConsole(directives map[string][]string, issues *[]CSPIssue) {
	if values, ok := directives["connect-src"]; ok {
		found := false
		for _, val := range values {
			if strings.Contains(val, "console.aws.amazon.com/") {
				found = true
				break
			}
		}
		if !found {
			*issues = append(*issues, CSPIssue{"HIGH", "connect-src does not include AWS console specific path", "connect-src"})
		}
	}
}

// isValidWildcard checks if a wildcard is on the approved list
func isValidWildcard(val string) bool {
	valid := []string{
		"*.cdn.console.awsstatic.com",
		"*.console.aws.amazon.com",
		"*.signin.aws.amazon.com",
	}
	for _, v := range valid {
		if val == v {
			return true
		}
	}
	return false
}

// isValidCDNDomain matches known AWS CDN endpoints
func isValidCDNDomain(values []string) bool {
	pattern := regexp.MustCompile(`^https://[a-z0-9.-]+\.cdn\.console\.awsstatic\.com$`)
	for _, val := range values {
		if pattern.MatchString(val) {
			return true
		}
	}
	return false
}

// contains checks if a slice contains a specifc string
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}