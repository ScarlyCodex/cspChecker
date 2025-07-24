package main

import (
    "flag"
    "fmt"
    "os"
    "regexp"
    "strings"
)

type CSPIssue struct {
    Message   string
    Directive string
}

type IssueGroup struct {
    Title   string
    Details []string
}

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
        fmt.Println("Usage: ./cspChecker -i <input-csp.txt> [-o <output.md>]")
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
        printFormattedIssues(issues)
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


func printBanner() {
    fmt.Println(colorCyan + "╔════════════════════════════════╗")
    fmt.Println("║        CSP ANALYZER            ║")
    fmt.Println("╚════════════════════════════════╝" + colorReset)
}

func printSuccess(msg string) {
    fmt.Println(colorCyan + "[✓] " + msg + colorReset)
}

func printError(msg string) {
    fmt.Println(colorRed + "[!] " + msg + colorReset)
}

//func printIssue(issue CSPIssue) {
   // fmt.Printf("%s[*] %s (Directive: %s)%s\n", colorYellow, issue.Message, issue.Directive, colorReset)
//}

func printFormattedIssues(issues []CSPIssue) {
    groups := groupIssues(issues)

    for i, group := range groups {
        fmt.Printf("%s%d. %s:%s\n", colorCyan, i+1, group.Title, colorReset)
        for _, detail := range group.Details {
            fmt.Printf("%s- %s%s\n", colorYellow, detail, colorReset)
        }
        fmt.Println() // Add an empty line between groups
    }
}


func saveReport(filename string, issues []CSPIssue) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    if len(issues) == 0 {
        fmt.Fprintln(file, "No CSP issues found.")
        return nil
    }

    groups := groupIssues(issues)

    for i, group := range groups {
        fmt.Fprintf(file, "%d. %s:\n", i+1, group.Title)
        for _, detail := range group.Details {
            fmt.Fprintf(file, "- %s\n", detail)
        }
        fmt.Fprintln(file)
    }

    return nil
}

func groupIssues(issues []CSPIssue) []IssueGroup {
    groups := make(map[string]*IssueGroup)
    
    for _, issue := range issues {
        var groupTitle string
        var detail string

        switch {
        case strings.Contains(issue.Message, "'self'"):
            groupTitle = "Use of `'self'` directive"
            detail = fmt.Sprintf("Found in `%s` - Should use specific path prefixes instead", issue.Directive)
            
        case strings.Contains(issue.Message, "required"):
            groupTitle = "Missing Required Directives"
            detail = fmt.Sprintf("`%s`: %s", issue.Directive, issue.Message)
            
        case strings.Contains(issue.Message, "unsafe-"):
            groupTitle = "Unsafe Directives Usage"
            detail = fmt.Sprintf("`%s` contains %s", issue.Directive, issue.Message)
            
        case strings.Contains(issue.Message, "URL format"):
            groupTitle = "Invalid URL Patterns"
            detail = fmt.Sprintf("In `%s`: %s", issue.Directive, issue.Message)
            
        case strings.Contains(issue.Message, "duplicate"):
            groupTitle = "Duplicate Entries"
            detail = fmt.Sprintf("In `%s`: %s", issue.Directive, issue.Message)
            
        default:
            groupTitle = "Other Configuration Issues"
            detail = fmt.Sprintf("%s in `%s`", issue.Message, issue.Directive)
        }

        if group, exists := groups[groupTitle]; exists {
            group.Details = append(group.Details, detail)
        } else {
            groups[groupTitle] = &IssueGroup{
                Title:   groupTitle,
                Details: []string{detail},
            }
        }
    }

    result := make([]IssueGroup, 0, len(groups))
    for _, group := range groups {
        result = append(result, *group)
    }

    return result
}

func analyzeCSP(csp string) []CSPIssue {
    var issues []CSPIssue
    directives := parseCSP(csp)

    // Run all validations
    checkRequiredDirectives(&issues)
    checkProhibitedDirectives(directives, &issues)
    checkDirectiveValues(directives, &issues)
    checkSelfDirective(directives, &issues)
    checkDuplicateValues(directives, &issues)
    checkURLFormat(directives, &issues)
    checkAllowedDomains(directives, &issues)
    checkStyleSrcInline(directives, &issues)
    verifyS3Domains(directives, &issues)
    verifyAWSConsole(directives, &issues)
    checkFormAction(directives, &issues)
    checkConnectSrcPaths(directives, &issues)

    return issues
}

func parseCSP(csp string) map[string][]string {
    directives := make(map[string][]string)
    csp = strings.TrimPrefix(csp, "Content-Security-Policy:")
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

func checkRequiredDirectives(issues *[]CSPIssue) {
    requiredDirectives := map[string]string{
        "default-src": "Required as fallback for other fetch directives",
        "script-src":  "Required to control script execution",
        "style-src":   "Required with 'unsafe-inline' for Console Navigation",
        "connect-src": "Required for AWS API calls",
        "object-src":  "Must be set to 'none'",
        "form-action": "Required for Switch Role functionality",
    }

    for dir, reason := range requiredDirectives {
        *issues = append(*issues, CSPIssue{
            Message:   fmt.Sprintf("%s - %s", dir, reason),
            Directive: dir,
        })
    }
}

func checkProhibitedDirectives(directives map[string][]string, issues *[]CSPIssue) {
    prohibitedDirectives := []string{
        "plugin-types",
        "block-all-mixed-content",
    }

    for _, dir := range prohibitedDirectives {
        if _, ok := directives[dir]; ok {
            *issues = append(*issues, CSPIssue{
                Message:   fmt.Sprintf("Prohibited directive according to AWS: %s", dir),
                Directive: dir,
            })
        }
    }
}

func checkDirectiveValues(directives map[string][]string, issues *[]CSPIssue) {
    dangerousValues := []string{"'unsafe-eval'", "*", "'strict-dynamic'"}
    
    for dir, values := range directives {
        if len(values) == 0 && dir != "upgrade-insecure-requests" {
            *issues = append(*issues, CSPIssue{
                Message:   "Directive without defined values",
                Directive: dir,
            })
            continue
        }

        for _, val := range values {
            if strings.HasPrefix(val, "http:") {
                *issues = append(*issues, CSPIssue{
                    Message:   "Use of insecure HTTP resource",
                    Directive: dir,
                })
            }
            for _, danger := range dangerousValues {
                if val == danger {
                    *issues = append(*issues, CSPIssue{
                        Message:   fmt.Sprintf("Use of dangerous value: %s", val),
                        Directive: dir,
                    })
                }
            }
        }
    }
}

func checkSelfDirective(directives map[string][]string, issues *[]CSPIssue) {
    for dir, values := range directives {
        if contains(values, "'self'") {
            *issues = append(*issues, CSPIssue{
                Message:   "Use of 'self' breaks console isolation - use specific paths instead",
                Directive: dir,
            })
        }
    }
}

func checkDuplicateValues(directives map[string][]string, issues *[]CSPIssue) {
    for dir, values := range directives {
        seen := make(map[string]bool)
        for _, val := range values {
            if seen[val] {
                *issues = append(*issues, CSPIssue{
                    Message:   fmt.Sprintf("Duplicate value found: %s", val),
                    Directive: dir,
                })
            }
            seen[val] = true
        }
    }
}

func checkURLFormat(directives map[string][]string, issues *[]CSPIssue) {
    pattern := regexp.MustCompile(`^https://[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+/[a-zA-Z0-9-_/]+/?$`)
    for dir, values := range directives {
        for _, val := range values {
            if strings.HasPrefix(val, "https://") && !pattern.MatchString(val) {
                *issues = append(*issues, CSPIssue{
                    Message:   fmt.Sprintf("Invalid URL format: %s", val),
                    Directive: dir,
                })
            }
        }
    }
}

func checkAllowedDomains(directives map[string][]string, issues *[]CSPIssue) {
    allowedDomains := []string{
        ".a2z.com",
        ".a2z.org.cn",
        ".aka.corp.amazon.com",
        ".aka.amazon.com",
        ".aws.dev",
        ".amazonaws.com",
        ".amazon.com",
    }
    
    for dir, values := range directives {
        for _, val := range values {
            if strings.HasPrefix(val, "https://") {
                isAllowed := false
                for _, domain := range allowedDomains {
                    if strings.Contains(val, domain) {
                        isAllowed = true
                        break
                    }
                }
                if !isAllowed {
                    *issues = append(*issues, CSPIssue{
                        Message:   fmt.Sprintf("Domain not in allowed list: %s", val),
                        Directive: dir,
                    })
                }
            }
        }
    }
}

func checkStyleSrcInline(directives map[string][]string, issues *[]CSPIssue) {
    if values, ok := directives["style-src"]; ok {
        if !contains(values, "'unsafe-inline'") {
            *issues = append(*issues, CSPIssue{
                Message:   "style-src missing required 'unsafe-inline' for Console Navigation",
                Directive: "style-src",
            })
        }
    }
}

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
                *issues = append(*issues, CSPIssue{
                    Message:   "Using S3 in directive not allowed by AWS",
                    Directive: dir,
                })
            }
        }
    }
}

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
            *issues = append(*issues, CSPIssue{
                Message:   "connect-src does not include AWS console specific path",
                Directive: "connect-src",
            })
        }
    }
}

func checkFormAction(directives map[string][]string, issues *[]CSPIssue) {
    if values, ok := directives["form-action"]; ok {
        if len(values) == 0 {
            *issues = append(*issues, CSPIssue{
                Message:   "form-action must be set to either 'none' or specific URLs",
                Directive: "form-action",
            })
        }
        for _, val := range values {
            if val != "'none'" && !strings.HasPrefix(val, "https://") {
                *issues = append(*issues, CSPIssue{
                    Message:   fmt.Sprintf("Invalid form-action value: %s", val),
                    Directive: "form-action",
                })
            }
        }
    }
}

func checkConnectSrcPaths(directives map[string][]string, issues *[]CSPIssue) {
    if values, ok := directives["connect-src"]; ok {
        validPathFound := false
        for _, val := range values {
            if strings.Contains(val, "console.aws.amazon.com/") {
                validPathFound = true
                break
            }
        }
        if !validPathFound {
            *issues = append(*issues, CSPIssue{
                Message:   "connect-src should include specific console paths",
                Directive: "connect-src",
            })
        }
    }
}

func contains(slice []string, s string) bool {
    for _, v := range slice {
        if v == s {
            return true
        }
    }
    return false
}

func isValidWildcard(val string) bool {
    valid := []string{
        "*.cdn.console.awsstatic.com",
        "*.console.aws.amazon.com",
        "*.signin.aws.amazon.com",
        "*.ccs.amazonaws.com",
    }
    for _, v := range valid {
        if val == v {
            return true
        }
    }
    return false
}

func isValidCDNDomain(values []string) bool {
    pattern := regexp.MustCompile(`^https://[a-z0-9.-]+\.cdn\.console\.awsstatic\.com$`)
    for _, val := range values {
        if pattern.MatchString(val) {
            return true
        }
    }
    return false
}

// Función auxiliar para validar URLs específicas de AWS
func isAWSUrl(url string) bool {
    awsPatterns := []string{
        `^https://[a-z0-9-]+\.console\.aws\.amazon\.com/`,
        `^https://[a-z0-9-]+\.amazonaws\.com/`,
        `^https://[a-z0-9-]+\.awsstatic\.com/`,
    }

    for _, pattern := range awsPatterns {
        if matched, _ := regexp.MatchString(pattern, url); matched {
            return true
        }
    }
    return false
}

// Función auxiliar para validar dominios específicos
func isAllowedDomain(domain string, allowList []string) bool {
    for _, allowed := range allowList {
        if strings.HasSuffix(domain, allowed) {
            return true
        }
    }
    return false
}

// Función auxiliar para limpiar URLs
func cleanUrl(url string) string {
    url = strings.TrimSpace(url)
    url = strings.TrimSuffix(url, "/")
    return url
}
