package reporter

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type HTMLReportData struct {
	APKName         string
	PackageName     string
	Version         string
	MinSdkVersion   string
	ScanTime        string
	TotalFindings   int
	Categories      map[string]CategoryData
	Vulnerabilities []VulnerabilityData
	Summary         SummaryData
}

type CategoryData struct {
	Name     string
	Count    int
	Findings []FindingData
}

type FindingData struct {
	File    string
	Match   string
	Context string
}

type VulnerabilityData struct {
	Type        string
	Severity    string
	Description string
	Details     string
}

type SummaryData struct {
	TotalFiles      int
	TotalPatterns   int
	Vulnerabilities int
	HighRisk        int
}

func GenerateHTMLReport(data HTMLReportData) (string, error) {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"gt":         func(a, b int) bool { return a > b },
		"stripAnsi":  stripAnsiCodes,
		"formatText": formatText,
		"splitLines": func(s string) []string { return strings.Split(s, "\n") },
	}).Parse(htmlTemplate))

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func stripAnsiCodes(text string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(text, "")
}

func formatText(text string) string {
	text = stripAnsiCodes(text)
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	text = regexp.MustCompile(`(❯ [A-Za-z]+:)`).ReplaceAllString(text, "\n\n$1")
	text = regexp.MustCompile(`(• [A-Za-z])`).ReplaceAllString(text, "\n$1")
	text = regexp.MustCompile(`(│ [A-Za-z])`).ReplaceAllString(text, "\n$1")
	text = regexp.MustCompile(`(╭─ [A-Za-z]+)`).ReplaceAllString(text, "\n\n$1")
	text = regexp.MustCompile(`(╰─)`).ReplaceAllString(text, "\n$1")
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\n{3,}`).ReplaceAllString(text, "\n\n")
	return text
}

func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "ℹ️"
	}
}

// ExtractMinSdkVersion extracts minSdkVersion from AndroidManifest.xml
func ExtractMinSdkVersion(decompileDir string) string {
	// Look for AndroidManifest.xml in common decompilation output locations
	manifestPaths := []string{
		filepath.Join(decompileDir, "AndroidManifest.xml"),
		filepath.Join(decompileDir, "sources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "resources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "res", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "resources", "com.jbl.oneapp.apk", "AndroidManifest.xml"),
	}

	var manifestPath string
	for _, path := range manifestPaths {
		if _, err := os.Stat(path); err == nil {
			manifestPath = path
			break
		}
	}

	if manifestPath == "" {
		return ""
	}

	// Read the AndroidManifest.xml file
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return ""
	}

	manifestContent := string(content)

	// Extract minSdkVersion using regex
	minSdkRegex := regexp.MustCompile(`android:minSdkVersion\s*=\s*["'](\d+)["']`)
	if matches := minSdkRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		return matches[1]
	}

	// Try alternative pattern without quotes
	minSdkRegex2 := regexp.MustCompile(`android:minSdkVersion\s*=\s*(\d+)`)
	if matches := minSdkRegex2.FindStringSubmatch(manifestContent); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// ExtractPackageInfo extracts package name and version from AndroidManifest.xml
func ExtractPackageInfo(decompileDir string) (packageName, version string) {
	// Look for AndroidManifest.xml in common decompilation output locations
	manifestPaths := []string{
		filepath.Join(decompileDir, "AndroidManifest.xml"),
		filepath.Join(decompileDir, "sources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "resources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "res", "AndroidManifest.xml"),
	}

	var manifestPath string
	for _, path := range manifestPaths {
		if _, err := os.Stat(path); err == nil {
			manifestPath = path
			break
		}
	}

	if manifestPath == "" {
		return "", ""
	}

	// Read the AndroidManifest.xml file
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", ""
	}

	manifestContent := string(content)

	// Extract package name
	packageRegex := regexp.MustCompile(`package\s*=\s*["']([^"']+)["']`)
	if matches := packageRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		packageName = matches[1]
	}

	// Extract version name
	versionRegex := regexp.MustCompile(`android:versionName\s*=\s*["']([^"']+)["']`)
	if matches := versionRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		version = matches[1]
	}

	// If version name not found, try version code
	if version == "" {
		versionCodeRegex := regexp.MustCompile(`android:versionCode\s*=\s*["']([^"']+)["']`)
		if matches := versionCodeRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
			version = "v" + matches[1]
		}
	}

	return packageName, version
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Security Analysis Report - {{.APKName}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #3a3a3a;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --text-muted: #808080;
            --accent-primary: #00d4ff;
            --accent-secondary: #0099cc;
            --danger: #ff4757;
            --warning: #ffa502;
            --success: #2ed573;
            --border-color: #404040;
            --shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }
        
        body {
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-primary);
            min-height: 100vh;
            display: flex;
        }
        
        /* Sidebar */
        .sidebar {
            width: 320px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            z-index: 1000;
            transition: transform 0.3s ease;
            box-shadow: var(--shadow);
        }
        
        .sidebar.collapsed {
            transform: translateX(-100%);
        }
        
        .sidebar-header {
            padding: 24px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }
        
        .sidebar-header h2 {
            font-size: 1.4em;
            margin-bottom: 8px;
            color: var(--accent-primary);
        }
        
        .sidebar-header .subtitle {
            font-size: 0.9em;
            color: var(--text-secondary);
        }
        
        .nav-section {
            margin-bottom: 32px;
        }
        
        .nav-section h3 {
            padding: 0 24px 12px;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 12px;
        }
        
        .nav-item {
            display: block;
            padding: 16px 24px;
            color: var(--text-primary);
            text-decoration: none;
            transition: all 0.3s ease;
            border-left: 3px solid transparent;
            cursor: pointer;
            position: relative;
        }
        
        .nav-item:hover {
            background: var(--bg-tertiary);
            border-left-color: var(--accent-primary);
            transform: translateX(4px);
        }
        
        .nav-item.active {
            background: var(--bg-tertiary);
            border-left-color: var(--accent-primary);
        }
        
        .nav-item .count {
            float: right;
            background: var(--danger);
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
            min-width: 20px;
            text-align: center;
        }
        
        .nav-item .count.zero {
            background: var(--text-muted);
        }
        
        .nav-item .count.success {
            background: var(--success);
        }
        
        /* Controls */
        .controls {
            padding: 0 24px 24px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .control-group {
            margin-bottom: 20px;
        }
        
        .control-group label {
            display: block;
            font-size: 0.85em;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .control-group select,
        .control-group input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-size: 0.9em;
            transition: all 0.3s ease;
        }
        
        .control-group select:focus,
        .control-group input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
        }
        
        .control-group input::placeholder {
            color: var(--text-muted);
        }
        
        .toggle-btn {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            width: 100%;
            margin-bottom: 12px;
            transition: all 0.3s ease;
        }
        
        .toggle-btn:hover {
            background: var(--accent-secondary);
            transform: translateY(-2px);
        }
        
        .toggle-btn.active {
            background: var(--danger);
        }
        
        /* Main content */
        .main-content {
            flex: 1;
            margin-left: 320px;
            transition: margin-left 0.3s ease;
        }
        
        .main-content.expanded {
            margin-left: 0;
        }
        
        .top-bar {
            background: var(--bg-secondary);
            padding: 20px 32px;
            box-shadow: var(--shadow);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            border-bottom: 1px solid var(--border-color);
        }
        
        .menu-toggle {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .menu-toggle:hover {
            background: var(--accent-secondary);
            transform: translateY(-2px);
        }
        
        .view-controls {
            display: flex;
            gap: 12px;
            align-items: center;
        }
        
        .view-toggle {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9em;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }
        
        .view-toggle:hover {
            background: var(--bg-primary);
            border-color: var(--accent-primary);
        }
        
        .view-toggle.active {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border-color: var(--accent-primary);
        }
        
        .export-btn {
            background: var(--success);
            color: var(--bg-primary);
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .export-btn:hover {
            background: #26c965;
            transform: translateY(-2px);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 32px;
        }
        
        .header {
            background: var(--bg-secondary);
            color: var(--text-primary);
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 32px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        
        .header h1 {
            font-size: 2.8em;
            margin-bottom: 16px;
            font-weight: 700;
            color: var(--accent-primary);
        }
        
        .header .subtitle {
            font-size: 1.3em;
            opacity: 0.9;
            font-weight: 500;
        }
        
        /* Content sections */
        .content-section {
            display: none;
            background: var(--bg-secondary);
            padding: 32px;
            border-radius: 16px;
            box-shadow: var(--shadow);
            margin-bottom: 32px;
            border: 1px solid var(--border-color);
        }
        
        .content-section.active {
            display: block;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--accent-primary);
        }
        
        .section-title {
            font-size: 2em;
            color: var(--text-primary);
            margin: 0;
            font-weight: 700;
        }
        
        .section-stats {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .stat-item {
            text-align: center;
            padding: 16px 20px;
            background: var(--bg-tertiary);
            border-radius: 12px;
            border-left: 4px solid var(--accent-primary);
            min-width: 100px;
        }
        
        .stat-number {
            font-size: 1.8em;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .stat-label {
            font-size: 0.9em;
            color: var(--text-secondary);
            margin-top: 8px;
            font-weight: 500;
        }
        
        /* Filter and search */
        .filter-bar {
            background: var(--bg-tertiary);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 24px;
            display: flex;
            gap: 20px;
            align-items: center;
            flex-wrap: wrap;
            border: 1px solid var(--border-color);
        }
        
        .filter-group {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .filter-group label {
            font-weight: 600;
            color: var(--text-primary);
            white-space: nowrap;
        }
        
        .filter-group select,
        .filter-group input {
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 0.9em;
        }
        
        .search-box {
            flex: 1;
            min-width: 250px;
        }
        
        .search-box input {
            width: 100%;
            padding: 14px 20px;
            border: 1px solid var(--border-color);
            border-radius: 25px;
            font-size: 0.9em;
            background: var(--bg-secondary);
            color: var(--text-primary);
        }
        
        .search-box input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
        }
        
        /* Summary cards */
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            margin-bottom: 32px;
        }
        
        .card {
            background: var(--bg-secondary);
            padding: 28px;
            border-radius: 16px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
            border-color: var(--accent-primary);
        }
        
        .card-icon {
            font-size: 2.5em;
            opacity: 0.8;
            flex-shrink: 0;
        }
        
        .card-content {
            flex: 1;
        }
        
        .card h3 {
            color: var(--text-secondary);
            margin-bottom: 8px;
            font-size: 1em;
            font-weight: 500;
        }
        
        .card .number {
            font-size: 2.4em;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1;
        }
        
        /* Vulnerabilities */
        .vulnerability {
            border-left: 4px solid var(--accent-primary);
            padding: 24px;
            margin: 24px 0;
            background: var(--bg-tertiary);
            border-radius: 0 12px 12px 0;
            border: 1px solid var(--border-color);
        }
        
        .vulnerability-header {
            display: flex;
            align-items: center;
            margin-bottom: 16px;
        }
        
        .severity-badge {
            padding: 8px 16px;
            border-radius: 20px;
            color: white;
            font-weight: 700;
            margin-right: 16px;
            font-size: 0.9em;
        }
        
        .severity-high { background-color: var(--danger); }
        .severity-medium { background-color: var(--warning); color: var(--bg-primary); }
        .severity-low { background-color: var(--success); }
        
        .vulnerability h3 {
            color: var(--text-primary);
            margin-bottom: 12px;
            font-size: 1.3em;
        }
        
        .vulnerability-section {
            margin: 16px 0;
        }
        
        .vulnerability-section h4 {
            color: var(--accent-primary);
            margin-bottom: 8px;
            font-size: 1.1em;
        }
        
        /* Findings */
        .category {
            margin: 32px 0;
            padding: 24px;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            background: var(--bg-secondary);
        }
        
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 2px solid var(--accent-primary);
        }
        
        .category h3 {
            color: var(--accent-primary);
            font-size: 1.5em;
            font-weight: 700;
        }
        
        .count-badge {
            background: var(--accent-primary);
            color: var(--bg-primary);
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.9em;
        }
        
        .finding {
            background: var(--bg-tertiary);
            padding: 20px;
            margin: 16px 0;
            border-radius: 8px;
            border-left: 4px solid var(--accent-primary);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border-color);
        }
        
        .finding-file {
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 12px;
            font-size: 1.1em;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .finding-match {
            background: var(--bg-primary);
            padding: 16px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            margin: 12px 0;
            word-break: break-all;
            border: 1px solid var(--border-color);
            font-size: 0.9em;
            color: var(--text-secondary);
        }
        
        .finding-context {
            color: var(--text-secondary);
            font-size: 0.9em;
            background: var(--bg-primary);
            padding: 16px;
            border-radius: 8px;
            margin-top: 12px;
            word-break: break-word;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
            border-left: 3px solid var(--accent-primary);
            border: 1px solid var(--border-color);
        }
        
        .finding-context pre {
            margin: 0;
            padding: 0;
            background: transparent;
            border: none;
            font-family: inherit;
            white-space: pre-wrap;
            word-break: break-word;
        }
        
        .context-preview {
            background: var(--bg-secondary);
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 12px;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.4;
            white-space: pre-wrap;
            color: var(--text-secondary);
            max-height: 200px;
            overflow: hidden;
            position: relative;
        }
        
        .context-preview::after {
            content: '...';
            position: absolute;
            bottom: 0;
            right: 0;
            background: var(--bg-secondary);
            padding: 0 8px;
            color: var(--text-muted);
        }
        
        .context-toggle {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85em;
            font-weight: 600;
            margin-top: 8px;
            transition: all 0.3s ease;
        }
        
        .context-toggle:hover {
            background: var(--accent-secondary);
            transform: translateY(-1px);
        }
        
        .context-full {
            display: block;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 24px 0;
            gap: 12px;
        }
        
        .pagination button {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .pagination button:hover {
            background: var(--accent-secondary);
            transform: translateY(-2px);
        }
        
        .pagination button:disabled {
            background: var(--text-muted);
            cursor: not-allowed;
            transform: none;
        }
        
        .pagination .current {
            background: var(--accent-secondary);
            font-weight: 700;
        }
        
        .footer {
            text-align: center;
            padding: 32px;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
            margin-top: 32px;
        }
        
        .no-findings {
            text-align: center;
            padding: 60px;
            color: var(--success);
            font-size: 1.3em;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                transform: translateX(-100%);
            }
            
            .sidebar:not(.collapsed) {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
        }
        
        /* Ensure sidebar is visible by default on larger screens, but still collapsible */
        @media (min-width: 769px) {
            .sidebar:not(.collapsed) {
                transform: translateX(0) !important;
            }
        }
        
        @media (max-width: 768px) {
            .top-bar {
                padding: 16px 20px;
            }
            
            .filter-bar {
                flex-direction: column;
                align-items: stretch;
            }
            
            .filter-group {
                justify-content: space-between;
            }
            
            .section-stats {
                flex-direction: column;
                gap: 12px;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <h2>🔍 APK Security Report</h2>
            <div class="subtitle">{{.APKName}}</div>
        </div>
        
        <div class="sidebar-content">
            <!-- Navigation -->
            <div class="nav-section">
                <h3>📊 Overview</h3>
                <a href="#" class="nav-item active" data-section="summary">
                    Summary <span class="count">{{.TotalFindings}}</span>
                </a>
                <a href="#" class="nav-item" data-section="vulnerabilities">
                    Vulnerabilities <span class="count">{{.Summary.Vulnerabilities}}</span>
                </a>
            </div>
            
            <div class="nav-section">
                <h3>🔍 Categories</h3>
                {{range .Categories}}
                {{if gt .Count 0}}
                <a href="#" class="nav-item" data-section="{{.Name}}">
                    {{.Name}} <span class="count">{{.Count}}</span>
                </a>
                {{end}}
                {{end}}
            </div>
            
            <!-- Controls -->
            <div class="controls">
                <div class="control-group">
                    <label>View Mode</label>
                    <button class="toggle-btn active" id="toggle-compact">Compact View</button>
                    <button class="toggle-btn" id="toggle-detailed">Detailed View</button>
                </div>
                
                <div class="control-group">
                    <label>Show Context</label>
                    <button class="toggle-btn active" id="toggle-context" disabled>Context Always Shown</button>
                </div>
                
                <div class="control-group">
                    <label>Items per page</label>
                    <select id="perPageSelect">
                        <option value="10">10</option>
                        <option value="25" selected>25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content" id="mainContent">
        <!-- Top Bar -->
        <div class="top-bar">
            <button class="menu-toggle" id="menuToggle">☰ Menu</button>
            <div class="view-controls">
                <button class="view-toggle active" id="viewAll">All</button>
                <button class="view-toggle" id="viewHigh">High Risk</button>
                <button class="view-toggle" id="viewMedium">Medium Risk</button>
                <button class="view-toggle" id="viewLow">Low Risk</button>
                <button class="export-btn" id="exportBtn">📥 Export</button>
            </div>
        </div>
        
        <div class="container">
            <div class="header">
                <h1>🔍 APK Security Analysis Report</h1>
                <div class="subtitle">
                    <strong>APK:</strong> {{.APKName}}<br>
                    {{if .PackageName}}<strong>Package:</strong> {{.PackageName}}<br>{{end}}
                    {{if .Version}}<strong>Version:</strong> {{.Version}}<br>{{end}}
                    {{if .MinSdkVersion}}<strong>Min SDK:</strong> {{.MinSdkVersion}}<br>{{end}}
                    <strong>Scan Time:</strong> {{.ScanTime}}<br>
                    <strong>Total Findings:</strong> {{.TotalFindings}}
                </div>
            </div>
        
            <!-- Summary Section -->
            <div class="content-section active" id="summary-section">
                <div class="section-header">
                    <h2 class="section-title">📊 Analysis Summary</h2>
                </div>
                
                <div class="summary-cards">
                    <div class="card">
                        <div class="card-icon">📁</div>
                        <div class="card-content">
                            <h3>Files Analyzed</h3>
                            <div class="number">{{.Summary.TotalFiles}}</div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-icon">🔍</div>
                        <div class="card-content">
                            <h3>Patterns Scanned</h3>
                            <div class="number">{{.Summary.TotalPatterns}}</div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-icon">⚠️</div>
                        <div class="card-content">
                            <h3>Vulnerabilities</h3>
                            <div class="number">{{.Summary.Vulnerabilities}}</div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-icon">🔴</div>
                        <div class="card-content">
                            <h3>High Risk</h3>
                            <div class="number" style="color: var(--danger);">{{.Summary.HighRisk}}</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Vulnerabilities Section -->
            {{if .Vulnerabilities}}
            <div class="content-section" id="vulnerabilities-section">
                <div class="section-header">
                    <h2 class="section-title">🚨 Security Vulnerabilities</h2>
                    <div class="section-stats">
                        <div class="stat-item">
                            <div class="stat-number">{{len .Vulnerabilities}}</div>
                            <div class="stat-label">Total</div>
                        </div>
                    </div>
                </div>
                
                <div class="filter-bar">
                    <div class="search-box">
                        <input type="text" id="vulnSearch" placeholder="Search vulnerabilities...">
                    </div>
                    <div class="filter-group">
                        <label>Severity:</label>
                        <select id="severityFilter">
                            <option value="all">All</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                </div>
                
                <div class="vulnerabilities">
                    {{range .Vulnerabilities}}
                    <div class="vulnerability">
                        <div class="vulnerability-header">
                            <span class="severity-badge severity-{{.Severity}}">{{.Severity}}</span>
                            <h3>{{.Type}}</h3>
                        </div>
                        <div class="vulnerability-section">
                            <h4>Description</h4>
                            <p>{{.Description}}</p>
                        </div>
                        {{if .Details}}
                        <div class="vulnerability-section">
                            <h4>Details</h4>
                            <pre style="background: var(--bg-primary); padding: 16px; border-radius: 8px; overflow-x: auto; color: var(--text-secondary);">{{.Details}}</pre>
                        </div>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
            
            <!-- Categories Sections -->
            {{if .Categories}}
            {{$hasFindings := false}}
            {{range $category, $data := .Categories}}
            {{if gt $data.Count 0}}
            {{$hasFindings = true}}
            <div class="content-section" id="{{$category}}-section">
                <div class="section-header">
                    <h2 class="section-title">🔍 {{$data.Name}}</h2>
                    <div class="section-stats">
                        <div class="stat-item">
                            <div class="stat-number">{{$data.Count}}</div>
                            <div class="stat-label">Findings</div>
                        </div>
                    </div>
                </div>
                
                <div class="filter-bar">
                    <div class="search-box">
                        <input type="text" id="{{$category}}Search" placeholder="Search in {{$data.Name}}...">
                    </div>
                    <div class="filter-group">
                        <label>Show:</label>
                        <select id="{{$category}}Filter">
                            <option value="all">All</option>
                            <option value="with-context">With Context</option>
                            <option value="without-context">Without Context</option>
                        </select>
                    </div>
                </div>
                
                <div class="category" data-category="{{$category}}">
                    <div class="findings-container" data-category="{{$category}}">
                        {{range $index, $finding := $data.Findings}}
                        <div class="finding" data-index="{{$index}}">
                            <div class="finding-file">{{$data.Name}}: {{.File | stripAnsi}}</div>
                            <div class="finding-match">{{.Match | stripAnsi}}</div>
                            {{if .Context}}
                            <div class="finding-context">
                                <strong>Context:</strong>
                                <div class="context-full" id="context-{{$category}}-{{$index}}">{{.Context | stripAnsi | formatText}}</div>
                            </div>
                            {{end}}
                        </div>
                        {{end}}
                    </div>
                    
                    <div class="pagination" id="pagination-{{$category}}">
                        <button onclick="previousPage('{{$category}}')" id="prev-{{$category}}">Previous</button>
                        <span id="page-info-{{$category}}">Page 1 of 1</span>
                        <button onclick="nextPage('{{$category}}')" id="next-{{$category}}">Next</button>
                    </div>
                </div>
            </div>
            {{end}}
            {{end}}
            {{if not $hasFindings}}
            <div class="no-findings">
                <h2>✅ No Security Issues Found</h2>
                <p>Great! No sensitive information or vulnerabilities were detected in this APK.</p>
            </div>
            {{end}}
            {{else}}
            <div class="no-findings">
                <h2>✅ No Security Issues Found</h2>
                <p>Great! No sensitive information or vulnerabilities were detected in this APK.</p>
            </div>
            {{end}}
            
            <div class="footer">
                <p>Generated by apkX Security Scanner on {{.ScanTime}}</p>
                <p>For more information, visit the apkX documentation</p>
            </div>
        </div>
    </div>
    
    <script>
        // Global state
        let currentSection = 'summary';
        let currentView = 'compact';
        let showContext = true;
        let currentPerPage = 25;
        let currentRiskFilter = 'all';
        
        // Initialize the application
        document.addEventListener('DOMContentLoaded', function() {
            initializeSidebar();
            initializeViewControls();
            initializeFilters();
            showSection('summary');
        });
        
        // Sidebar functionality
        function initializeSidebar() {
            const menuToggle = document.getElementById('menuToggle');
            const sidebar = document.getElementById('sidebar');
            const mainContent = document.getElementById('mainContent');
            
            menuToggle.addEventListener('click', function() {
                sidebar.classList.toggle('collapsed');
                mainContent.classList.toggle('expanded');
            });
            
            // Navigation items
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', function(e) {
                    e.preventDefault();
                    const section = this.dataset.section;
                    showSection(section);
                    
                    // Update active state
                    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                    this.classList.add('active');
                });
            });
        }
        
        // Show specific section
        function showSection(sectionName) {
            // Hide all sections
            document.querySelectorAll('.content-section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Show target section
            const targetSection = document.getElementById(sectionName + '-section');
            if (targetSection) {
                targetSection.classList.add('active');
                currentSection = sectionName;
            }
        }
        
        // View controls
        function initializeViewControls() {
            // View mode toggles
            document.getElementById('toggle-compact').addEventListener('click', function() {
                setViewMode('compact');
            });
            
            document.getElementById('toggle-detailed').addEventListener('click', function() {
                setViewMode('detailed');
            });
            
            // Context is always shown; disable the toggle button
            const contextBtn = document.getElementById('toggle-context');
            if (contextBtn) {
                contextBtn.disabled = true;
                contextBtn.textContent = 'Context Always Shown';
            }
            
            // Risk filter buttons
            document.getElementById('viewAll').addEventListener('click', function() {
                setRiskFilter('all');
            });
            
            document.getElementById('viewHigh').addEventListener('click', function() {
                setRiskFilter('high');
            });
            
            document.getElementById('viewMedium').addEventListener('click', function() {
                setRiskFilter('medium');
            });
            
            document.getElementById('viewLow').addEventListener('click', function() {
                setRiskFilter('low');
            });
            
            // Export button
            document.getElementById('exportBtn').addEventListener('click', function() {
                exportReport();
            });
        }
        
        // Set view mode
        function setViewMode(mode) {
            currentView = mode;
            document.querySelectorAll('.toggle-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('toggle-' + mode).classList.add('active');
            
            // Update finding display
            document.querySelectorAll('.finding').forEach(finding => {
                if (mode === 'compact') {
                    finding.classList.add('compact');
                } else {
                    finding.classList.remove('compact');
                }
            });
        }
        
        // Set risk filter
        function setRiskFilter(risk) {
            currentRiskFilter = risk;
            document.querySelectorAll('.view-toggle').forEach(btn => btn.classList.remove('active'));
            document.getElementById('view' + risk.charAt(0).toUpperCase() + risk.slice(1)).classList.add('active');
            
            // Filter findings by risk level
            filterFindingsByRisk(risk);
        }
        
        // Filter findings by risk level
        function filterFindingsByRisk(risk) {
            document.querySelectorAll('.finding').forEach(finding => {
                const severity = finding.querySelector('.severity-badge');
                if (severity) {
                    const findingRisk = severity.textContent.toLowerCase();
                    if (risk === 'all' || findingRisk === risk) {
                        finding.style.display = 'block';
                    } else {
                        finding.style.display = 'none';
                    }
                }
            });
        }
        
        // Initialize filters
        function initializeFilters() {
            // Search functionality
            document.querySelectorAll('input[type="text"]').forEach(input => {
                input.addEventListener('input', function() {
                    const searchTerm = this.value.toLowerCase();
                    const sectionId = this.id.replace('Search', '');
                    searchInSection(sectionId, searchTerm);
                });
            });
            
            // Filter dropdowns
            document.querySelectorAll('select').forEach(select => {
                select.addEventListener('change', function() {
                    const sectionId = this.id.replace('Filter', '');
                    applyFilters(sectionId);
                });
            });
        }
        
        // Search in section
        function searchInSection(sectionId, searchTerm) {
            const section = document.getElementById(sectionId + '-section');
            if (!section) return;
            
            const findings = section.querySelectorAll('.finding');
            findings.forEach(finding => {
                const text = finding.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }
        
        // Apply filters
        function applyFilters(sectionId) {
            const section = document.getElementById(sectionId + '-section');
            if (!section) return;
            
            const searchInput = document.getElementById(sectionId + 'Search');
            const filterSelect = document.getElementById(sectionId + 'Filter');
            
            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            const filterValue = filterSelect ? filterSelect.value : 'all';
            
            const findings = section.querySelectorAll('.finding');
            findings.forEach(finding => {
                const text = finding.textContent.toLowerCase();
                const hasContext = finding.querySelector('.context-full') !== null;
                
                let showFinding = true;
                
                // Search filter
                if (searchTerm && !text.includes(searchTerm)) {
                    showFinding = false;
                }
                
                // Context filter
                if (filterValue === 'with-context' && !hasContext) {
                    showFinding = false;
                } else if (filterValue === 'without-context' && hasContext) {
                    showFinding = false;
                }
                
                finding.style.display = showFinding ? 'block' : 'none';
            });
        }
        
        // Update context visibility
        function updateContextVisibility() {
            document.querySelectorAll('.context-full').forEach(context => {
                context.style.display = 'block';
            });
        }
        
        // Export functionality
        function exportReport() {
            const data = {
                apkName: '{{.APKName}}',
                scanTime: '{{.ScanTime}}',
                totalFindings: {{.TotalFindings}},
                summary: {
                    totalFiles: {{.Summary.TotalFiles}},
                    totalPatterns: {{.Summary.TotalPatterns}},
                    vulnerabilities: {{.Summary.Vulnerabilities}},
                    highRisk: {{.Summary.HighRisk}}
                },
                currentSection: currentSection,
                currentView: currentView,
                showContext: showContext,
                riskFilter: currentRiskFilter
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'apkx-report-export.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        // Toggle context for individual findings
        function toggleContext(categoryName, index) {
            // No-op: full context is always visible now
            return;
        }
    </script>
</body>
</html>
`
