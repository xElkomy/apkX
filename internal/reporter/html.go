package reporter

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type HTMLReportData struct {
	APKName         string
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
	Type           string
	Severity       string
	Description    string
	Impact         string
	Recommendation string
	Details        string
}

type SummaryData struct {
	TotalFiles      int
	TotalPatterns   int
	Vulnerabilities int
	HighRisk        int
	MediumRisk      int
	LowRisk         int
}

func GenerateHTMLReport(data HTMLReportData, outputPath string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create HTML file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %v", err)
	}
	defer file.Close()

	// Parse and execute template with custom functions
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"gt": func(a, b int) bool {
			return a > b
		},
		"stripAnsi":  stripAnsiCodes,
		"formatText": formatText,
		"splitLines": func(s string) []string {
			return strings.Split(s, "\n")
		},
	}).Parse(htmlTemplate))
	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	return nil
}

// stripAnsiCodes removes ANSI escape codes from text
func stripAnsiCodes(text string) string {
	// Remove ANSI escape codes (e.g., [36m, [0m, [33m, etc.)
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(text, "")
}

// formatText improves text formatting for HTML display
func formatText(text string) string {
	// Strip ANSI codes first
	text = stripAnsiCodes(text)

	// Clean up extra whitespace
	text = strings.TrimSpace(text)

	// Replace multiple spaces with single space
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	// Add line breaks before common patterns for better readability
	text = regexp.MustCompile(`(❯ [A-Za-z]+:)`).ReplaceAllString(text, "\n\n$1")
	text = regexp.MustCompile(`(• [A-Za-z])`).ReplaceAllString(text, "\n$1")
	text = regexp.MustCompile(`(│ [A-Za-z])`).ReplaceAllString(text, "\n$1")
	text = regexp.MustCompile(`(╭─ [A-Za-z]+)`).ReplaceAllString(text, "\n\n$1")
	text = regexp.MustCompile(`(╰─)`).ReplaceAllString(text, "\n$1")

	// Clean up the text
	text = strings.TrimSpace(text)

	// Remove excessive line breaks
	text = regexp.MustCompile(`\n{3,}`).ReplaceAllString(text, "\n\n")

	return text
}

func GetSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "high", "critical":
		return "#dc3545"
	case "medium":
		return "#fd7e14"
	case "low":
		return "#ffc107"
	default:
		return "#6c757d"
	}
}

func GetSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "high", "critical":
		return "🔴"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "ℹ️"
	}
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
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .card h3 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .card .number {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        
        .vulnerabilities {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .vulnerability {
            border-left: 4px solid #667eea;
            padding: 20px;
            margin: 20px 0;
            background: #f8f9fa;
            border-radius: 0 10px 10px 0;
        }
        
        .vulnerability-header {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            margin-right: 15px;
        }
        
        .severity-high { background-color: #dc3545; }
        .severity-medium { background-color: #fd7e14; }
        .severity-low { background-color: #ffc107; color: #333; }
        
        .vulnerability h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .vulnerability-section {
            margin: 15px 0;
        }
        
        .vulnerability-section h4 {
            color: #667eea;
            margin-bottom: 8px;
        }
        
        .findings {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .category {
            margin: 30px 0;
            padding: 20px;
            border: 1px solid #e9ecef;
            border-radius: 10px;
        }
        
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .category h3 {
            color: #667eea;
        }
        
        .count-badge {
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
        }
        
        .finding {
            background: #f8f9fa;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .finding-file {
            font-weight: bold;
            color: #495057;
            margin-bottom: 10px;
            font-size: 1.1em;
            padding-bottom: 5px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .finding-match {
            background: #fff3cd;
            padding: 12px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            word-break: break-all;
            border: 1px solid #ffeaa7;
            font-size: 0.9em;
        }
        
        .finding-context {
            color: #6c757d;
            font-size: 0.9em;
            background: #f8f9fa;
            padding: 12px;
            border-radius: 5px;
            margin-top: 8px;
            word-break: break-word;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
            border-left: 3px solid #667eea;
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
            background: #e9ecef;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.4;
            white-space: pre-wrap;
        }
        
        .finding-context strong {
            color: #495057;
            font-size: 1em;
            display: block;
            margin-bottom: 8px;
        }
        
        .context-toggle {
            background: #667eea;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.8em;
            margin-top: 5px;
        }
        
        .context-toggle:hover {
            background: #5a6fd8;
        }
        
        .context-full {
            display: none;
        }
        
        .context-full.show {
            display: block;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 20px 0;
        }
        
        .pagination button {
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 0 5px;
            border-radius: 5px;
            cursor: pointer;
        }
        
        .pagination button:hover {
            background: #5a6fd8;
        }
        
        .pagination button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .pagination .current {
            background: #5a6fd8;
            font-weight: bold;
        }
        
        .findings-per-page {
            margin: 10px 0;
            text-align: center;
        }
        
        .findings-per-page select {
            padding: 5px;
            border-radius: 3px;
            border: 1px solid #ddd;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
            margin-top: 30px;
        }
        
        .no-findings {
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2em;
        }
        
        .toc {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .toc h3 {
            color: #667eea;
            margin-bottom: 15px;
        }
        
        .toc ul {
            list-style: none;
        }
        
        .toc li {
            margin: 8px 0;
        }
        
        .toc a {
            color: #667eea;
            text-decoration: none;
            padding: 5px 10px;
            border-radius: 5px;
            transition: background-color 0.3s;
        }
        
        .toc a:hover {
            background-color: #f8f9fa;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 APK Security Analysis Report</h1>
            <div class="subtitle">
                <strong>APK:</strong> {{.APKName}}<br>
                <strong>Scan Time:</strong> {{.ScanTime}}<br>
                <strong>Total Findings:</strong> {{.TotalFindings}}
            </div>
        </div>
        
        <div class="summary-cards">
            <div class="card">
                <h3>Total Files</h3>
                <div class="number">{{.Summary.TotalFiles}}</div>
            </div>
            <div class="card">
                <h3>Patterns Scanned</h3>
                <div class="number">{{.Summary.TotalPatterns}}</div>
            </div>
            <div class="card">
                <h3>Vulnerabilities</h3>
                <div class="number">{{.Summary.Vulnerabilities}}</div>
            </div>
            <div class="card">
                <h3>High Risk</h3>
                <div class="number" style="color: #dc3545;">{{.Summary.HighRisk}}</div>
            </div>
        </div>
        
        {{if .Vulnerabilities}}
        <div class="vulnerabilities">
            <h2>🚨 Security Vulnerabilities</h2>
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
                
                <div class="vulnerability-section">
                    <h4>Impact</h4>
                    <p>{{.Impact}}</p>
                </div>
                
                <div class="vulnerability-section">
                    <h4>Recommendation</h4>
                    <p>{{.Recommendation}}</p>
                </div>
                
                {{if .Details}}
                <div class="vulnerability-section">
                    <h4>Details</h4>
                    <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto;">{{.Details}}</pre>
                </div>
                {{end}}
            </div>
            {{end}}
        </div>
        {{end}}
        
        {{if .Categories}}
        <div class="findings">
            <h2>🔍 Security Findings</h2>
            
            <div class="findings-per-page">
                <label for="perPage">Findings per page:</label>
                <select id="perPage" onchange="changePerPage()">
                    <option value="10">10</option>
                    <option value="25" selected>25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                </select>
            </div>
            
            {{range $category, $data := .Categories}}
            <div class="category" data-category="{{$category}}">
                <div class="category-header">
                    <h3>{{$data.Name}}</h3>
                    <span class="count-badge">{{$data.Count}} findings</span>
                </div>
                
                <div class="findings-container" data-category="{{$category}}">
                    {{range $index, $finding := $data.Findings}}
                    <div class="finding" data-index="{{$index}}">
                        <div class="finding-file">{{$data.Name}}: {{.File | stripAnsi}}</div>
                        <div class="finding-match">{{.Match | stripAnsi}}</div>
                        {{if .Context}}
                        <div class="finding-context">
                            <strong>Context:</strong>
                            <div class="context-preview">{{.Context | stripAnsi | formatText}}</div>
                            <button class="context-toggle" onclick="toggleContext('{{$category}}', {{$index}})">Show Full Context</button>
                            <div class="context-full" id="context-{{$category}}-{{$index}}">
                                <pre>{{.Context | stripAnsi | formatText}}</pre>
                            </div>
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
            {{end}}
        </div>
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
    
    <script>
        // Pagination state
        const paginationState = {};
        let currentPerPage = 25;
        
        // Initialize pagination for all categories
        function initializePagination() {
            const categories = document.querySelectorAll('.category');
            categories.forEach(category => {
                const categoryName = category.dataset.category;
                const findings = category.querySelectorAll('.finding');
                const totalFindings = findings.length;
                const totalPages = Math.ceil(totalFindings / currentPerPage);
                
                paginationState[categoryName] = {
                    currentPage: 1,
                    totalPages: totalPages,
                    perPage: currentPerPage
                };
                
                updatePagination(categoryName);
            });
        }
        
        // Update pagination display
        function updatePagination(categoryName) {
            const state = paginationState[categoryName];
            const findings = document.querySelectorAll('[data-category="' + categoryName + '"] .finding');
            const startIndex = (state.currentPage - 1) * state.perPage;
            const endIndex = startIndex + state.perPage;
            
            // Hide all findings
            findings.forEach((finding, index) => {
                if (index >= startIndex && index < endIndex) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
            
            // Update pagination controls
            const prevBtn = document.getElementById('prev-' + categoryName);
            const nextBtn = document.getElementById('next-' + categoryName);
            const pageInfo = document.getElementById('page-info-' + categoryName);
            
            prevBtn.disabled = state.currentPage === 1;
            nextBtn.disabled = state.currentPage === state.totalPages;
            pageInfo.textContent = 'Page ' + state.currentPage + ' of ' + state.totalPages;
        }
        
        // Change findings per page
        function changePerPage() {
            currentPerPage = parseInt(document.getElementById('perPage').value);
            
            // Recalculate pagination for all categories
            const categories = document.querySelectorAll('.category');
            categories.forEach(category => {
                const categoryName = category.dataset.category;
                const findings = category.querySelectorAll('.finding');
                const totalFindings = findings.length;
                const totalPages = Math.ceil(totalFindings / currentPerPage);
                
                paginationState[categoryName] = {
                    currentPage: 1,
                    totalPages: totalPages,
                    perPage: currentPerPage
                };
                
                updatePagination(categoryName);
            });
        }
        
        // Previous page
        function previousPage(categoryName) {
            const state = paginationState[categoryName];
            if (state.currentPage > 1) {
                state.currentPage--;
                updatePagination(categoryName);
            }
        }
        
        // Next page
        function nextPage(categoryName) {
            const state = paginationState[categoryName];
            if (state.currentPage < state.totalPages) {
                state.currentPage++;
                updatePagination(categoryName);
            }
        }
        
        // Toggle context visibility
        function toggleContext(categoryName, index) {
            const contextFull = document.getElementById('context-' + categoryName + '-' + index);
            const button = event.target;
            
            if (contextFull.classList.contains('show')) {
                contextFull.classList.remove('show');
                button.textContent = 'Show Full Context';
            } else {
                contextFull.classList.add('show');
                button.textContent = 'Hide Context';
            }
        }
        
        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', function() {
            initializePagination();
        });
    </script>
</body>
</html>
`
