package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/apkX/internal/decompiler"
	"github.com/h0tak88r/apkX/internal/reporter"
	"github.com/h0tak88r/apkX/internal/utils"
	"gopkg.in/yaml.v3"
)

type Config struct {
	APKPath        string
	OutputDir      string
	PatternsPath   string
	Workers        int
	WebhookURL     string
	TaskHijackOnly bool
	HTMLOutput     bool
	JanusScan      bool
}

type APKScanner struct {
	config    *Config
	patterns  map[string][]string
	tempDir   string
	results   map[string][]string
	resultsMu sync.Mutex
	apkPkg    string
	cacheDir  string
	mu        sync.Mutex
	analyzers []AnalyzerInterface
}

type AnalyzerInterface interface {
	Analyze(decompileDir string) ([]string, error)
	SetAPKPath(apkPath string)
}

type Pattern struct {
	Name       string   `yaml:"name"`
	Regex      string   `yaml:"regex,omitempty"`
	Regexes    []string `yaml:"regexes,omitempty"`
	Confidence string   `yaml:"confidence"`
}

type PatternsConfig struct {
	Patterns []Pattern `yaml:"patterns"`
}

func NewAPKScanner(config *Config) *APKScanner {
	analyzers := []AnalyzerInterface{
		NewTaskHijackingAnalyzer(),
		NewInsecureStorageAnalyzer(),
		NewCertificatePinningAnalyzer(),
		NewDebugModeAnalyzer(),
	}

	if config.JanusScan {
		analyzers = append(analyzers, NewJanusVulnerabilityAnalyzer())
	}

	return &APKScanner{
		config:    config,
		results:   make(map[string][]string),
		analyzers: analyzers,
	}
}

func (s *APKScanner) Run() error {
	// Validate APK file
	if err := s.validateAPK(); err != nil {
		return err
	}

	// Try to use cached decompiled APK or decompile new one
	if err := s.decompileAPK(); err != nil {
		return fmt.Errorf("failed to decompile APK: %v", err)
	}

	// If task hijacking only mode is enabled, skip pattern scanning
	if s.config.TaskHijackOnly {
		fmt.Printf("%s** Scanning for Task Hijacking vulnerabilities...%s\n",
			utils.ColorBlue, utils.ColorEnd)

		analyzer := NewTaskHijackingAnalyzer()
		findings, err := analyzer.Analyze(s.tempDir)
		if err != nil {
			return fmt.Errorf("task hijacking analysis failed: %v", err)
		}

		// Print findings
		fmt.Printf("\n%s=== Task Hijacking Analysis Results ===%s\n",
			utils.ColorGreen, utils.ColorEnd)

		if len(findings) == 0 || (len(findings) == 1 && findings[0] == "No activities vulnerable to task hijacking were found.") {
			fmt.Printf("%sNo task hijacking vulnerabilities found.%s\n",
				utils.ColorGreen, utils.ColorEnd)
		} else {
			fmt.Printf("%sFound potential task hijacking vulnerabilities:%s\n",
				utils.ColorRed, utils.ColorEnd)
			for _, finding := range findings {
				fmt.Println(finding)
				fmt.Println("---")
			}
		}

		// Save results if output directory is specified
		if s.config.OutputDir != "" {
			results := map[string][]string{
				"Task Hijacking Vulnerabilities": findings,
			}
			return s.saveResults(results)
		}

		return nil
	}

	// Load patterns
	patterns, err := s.loadPatterns()
	if err != nil {
		return fmt.Errorf("failed to load patterns: %v", err)
	}

	// Process files concurrently
	results := make(map[string][]string)
	resultsMu := sync.Mutex{}
	var wg sync.WaitGroup

	// Collect all files first
	var filesToProcess []string
	err = filepath.Walk(s.tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && isRelevantFile(path) {
			filesToProcess = append(filesToProcess, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to collect files: %v", err)
	}

	fmt.Printf("%sAnalyzing %d files...%s\n", utils.ColorBlue, len(filesToProcess), utils.ColorEnd)

	// Process files in batches to control concurrency
	semaphore := make(chan struct{}, 10) // Limit concurrent goroutines

	for _, path := range filesToProcess {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			matches := s.processFile(filePath, patterns)
			if len(matches) > 0 {
				resultsMu.Lock()
				for pattern, found := range matches {
					if len(found) > 0 {
						results[pattern] = append(results[pattern], found...)
					}
				}
				resultsMu.Unlock()
			}
		}(path)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Run additional security analyzers
	for _, analyzer := range s.analyzers {
		// Set APK path for analyzers that need it
		analyzer.SetAPKPath(s.config.APKPath)

		findings, err := analyzer.Analyze(s.tempDir)
		if err != nil {
			fmt.Printf("%sWarning: Analyzer error: %v%s\n",
				utils.ColorWarning, err, utils.ColorEnd)
			continue
		}

		if len(findings) > 0 {
			// Use analyzer type name as category
			analyzerType := fmt.Sprintf("%T", analyzer)
			categoryName := strings.TrimPrefix(analyzerType, "*analyzer.")
			categoryName = strings.TrimSuffix(categoryName, "Analyzer")
			results[categoryName] = findings
		}
	}

	// Save results
	return s.saveResults(results)
}

func (s *APKScanner) validateAPK() error {
	if _, err := os.Stat(s.config.APKPath); os.IsNotExist(err) {
		return fmt.Errorf("APK file does not exist: %s", s.config.APKPath)
	}
	s.apkPkg = filepath.Base(s.config.APKPath)
	return nil
}

func (s *APKScanner) loadPatterns() (map[string][]string, error) {
	data, err := os.ReadFile(s.config.PatternsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read patterns file: %v", err)
	}

	var config PatternsConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse patterns YAML: %v", err)
	}

	// Validate and compile patterns
	s.patterns = make(map[string][]string)

	// Process patterns from single config
	for _, pattern := range config.Patterns {
		// Skip empty patterns
		if pattern.Name == "" || (pattern.Regex == "" && len(pattern.Regexes) == 0) {
			continue
		}

		var regexes []string
		if pattern.Regex != "" {
			regexes = []string{pattern.Regex}
		} else {
			regexes = pattern.Regexes
		}

		// Validate each regex
		validRegexes := make([]string, 0)
		for _, regex := range regexes {
			if _, err := regexp.Compile(regex); err != nil {
				fmt.Printf("%sWarning: Invalid regex pattern for '%s': %v%s\n",
					utils.ColorWarning, pattern.Name, err, utils.ColorEnd)
				continue
			}
			validRegexes = append(validRegexes, regex)
		}

		if len(validRegexes) > 0 {
			s.patterns[pattern.Name] = validRegexes
		}
	}

	if len(s.patterns) == 0 {
		return nil, fmt.Errorf("no valid patterns found in patterns file")
	}

	fmt.Printf("%s** Loaded %d patterns%s\n",
		utils.ColorBlue, len(s.patterns), utils.ColorEnd)
	return s.patterns, nil
}

func (s *APKScanner) processFile(path string, patterns map[string][]string) map[string][]string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	contentStr := string(content)
	matches := make(map[string][]string)
	seen := make(map[string]bool)

	// Get relative path for better output
	relPath := path
	if strings.Contains(path, s.tempDir) {
		if rel, err := filepath.Rel(s.tempDir, path); err == nil {
			relPath = rel
		}
	}

	for patternName, regexes := range patterns {
		for _, regex := range regexes {
			re, err := regexp.Compile(regex)
			if err != nil {
				continue
			}

			// Find all matches with some surrounding context
			allIndexes := re.FindAllStringIndex(contentStr, -1)
			if allIndexes == nil {
				continue
			}

			for _, idx := range allIndexes {
				match := contentStr[idx[0]:idx[1]]
				match = strings.TrimSpace(match)

				if match == "" || seen[match] {
					continue
				}

				// Skip common false positives
				if isCommonFalsePositive(match) {
					continue
				}

				// Get some context around the match
				start := max(0, idx[0]-100)
				end := min(len(contentStr), idx[1]+100)
				context := contentStr[start:end]
				context = strings.ReplaceAll(context, "\n", " ")
				context = strings.TrimSpace(context)

				result := fmt.Sprintf("%s: %s (Context: ...%s...)", relPath, match, context)
				matches[patternName] = append(matches[patternName], result)
				seen[match] = true
			}
		}
	}

	return matches
}

func isCommonFalsePositive(match string) bool {
	falsePositives := []string{
		"http://schemas.android.com/apk/res/android",
		"http://schemas.android.com/apk/res-auto",
		"http://schemas.android.com/aapt",
		"android.permission.",
		"android:name=",
		"android:label=",
		"android:value=",
		"android.intent.",
		"com.android.",
		"androidx.",
	}

	for _, fp := range falsePositives {
		if strings.Contains(match, fp) {
			return true
		}
	}

	return false
}

func (s *APKScanner) getCacheDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".apkx", "cache")
}

func (s *APKScanner) getApkHash() (string, error) {
	f, err := os.Open(s.config.APKPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (s *APKScanner) decompileAPK() error {
	// Setup cache directory in user's home
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %v", err)
	}

	s.cacheDir = filepath.Join(homeDir, ".apkx", "cache")
	if err := os.MkdirAll(s.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %v", err)
	}

	// Calculate APK hash for cache key
	hash, err := s.getApkHash()
	if err != nil {
		return fmt.Errorf("failed to calculate APK hash: %v", err)
	}

	// Check if cached version exists
	cachedDir := filepath.Join(s.cacheDir, hash)
	if _, err := os.Stat(cachedDir); err == nil {
		fmt.Printf("%s** Found cached decompiled APK, skipping decompilation...%s\n",
			utils.ColorBlue, utils.ColorEnd)
		s.tempDir = cachedDir
		return nil
	}

	// If not cached, create temporary directory for decompilation
	tempDir, err := os.MkdirTemp("", "apkx-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}

	// Initialize decompiler
	decompiler, err := decompiler.NewJadx()
	if err != nil {
		os.RemoveAll(tempDir)
		return fmt.Errorf("failed to initialize jadx: %v", err)
	}

	// Decompile APK
	fmt.Printf("%s** Decompiling APK (this may take a while)...%s\n",
		utils.ColorBlue, utils.ColorEnd)
	if err := decompiler.Decompile(s.config.APKPath, tempDir, ""); err != nil {
		// Check if we have any decompiled files before giving up
		if _, statErr := os.Stat(filepath.Join(tempDir, "sources")); statErr == nil {
			fmt.Printf("%s** Some decompilation errors occurred, but continuing with available files...%s\n",
				utils.ColorWarning, utils.ColorEnd)
		} else {
			os.RemoveAll(tempDir)
			return fmt.Errorf("failed to decompile APK: %v", err)
		}
	}

	// Move successful decompilation to cache
	if err := os.Rename(tempDir, cachedDir); err != nil {
		// If moving fails, try copying
		if copyErr := copyDir(tempDir, cachedDir); copyErr != nil {
			os.RemoveAll(tempDir)
			return fmt.Errorf("failed to cache decompiled APK: %v", copyErr)
		}
		os.RemoveAll(tempDir)
	}

	s.tempDir = cachedDir
	return nil
}

// Helper function to copy directory recursively
func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {

		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// Helper function to copy a single file
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Close()
}

func (s *APKScanner) sendToDiscord(jsonPath, htmlPath string) error {
	if s.config.WebhookURL == "" {
		return nil
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add JSON file
	jsonFile, err := os.Open(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %v", err)
	}
	defer jsonFile.Close()

	jsonPart, err := writer.CreateFormFile("file1", filepath.Base(jsonPath))
	if err != nil {
		return fmt.Errorf("failed to create JSON form file: %v", err)
	}

	_, err = io.Copy(jsonPart, jsonFile)
	if err != nil {
		return fmt.Errorf("failed to copy JSON file content: %v", err)
	}

	// Add HTML file
	htmlFile, err := os.Open(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to open HTML file: %v", err)
	}
	defer htmlFile.Close()

	htmlPart, err := writer.CreateFormFile("file2", filepath.Base(htmlPath))
	if err != nil {
		return fmt.Errorf("failed to create HTML form file: %v", err)
	}

	_, err = io.Copy(htmlPart, htmlFile)
	if err != nil {
		return fmt.Errorf("failed to copy HTML file content: %v", err)
	}

	// Add message field
	_ = writer.WriteField("content", fmt.Sprintf("APK Analysis Results for: %s\n\n📄 JSON Report: %s\n🌐 HTML Report: %s",
		s.apkPkg, filepath.Base(jsonPath), filepath.Base(htmlPath)))

	writer.Close()

	// Create and send request
	req, err := http.NewRequest("POST", s.config.WebhookURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("webhook request failed with status: %d", resp.StatusCode)
	}

	fmt.Printf("%sResults sent to Discord webhook successfully%s\n",
		utils.ColorGreen, utils.ColorEnd)
	return nil
}

func (s *APKScanner) saveResults(results map[string][]string) error {
	// Create statistics map for different finding types
	stats := make(map[string]int)

	// Count findings by category
	for category, matches := range results {
		if len(matches) > 0 {
			stats[category] = len(matches)
		}
	}

	// Print only the summary to terminal
	fmt.Printf("\n%s=== APK Analysis Summary ===%s\n", utils.ColorGreen, utils.ColorEnd)
	if len(stats) == 0 {
		fmt.Printf("%sNo sensitive information found.%s\n", utils.ColorYellow, utils.ColorEnd)
	} else {
		fmt.Printf("%sFound sensitive information in %d categories:%s\n",
			utils.ColorBlue, len(stats), utils.ColorEnd)

		for category, count := range stats {
			fmt.Printf("  • %s: %d findings\n", category, count)
		}
	}

	// Save detailed results to JSON file
	if s.config.OutputDir != "" {
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results to JSON: %v", err)
		}

		jsonPath := filepath.Join(s.config.OutputDir, "results.json")
		if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write results to file: %v", err)
		}
		fmt.Printf("\n%sDetailed results saved to: %s%s%s\n",
			utils.ColorBlue, utils.ColorGreen, jsonPath, utils.ColorEnd)

		// Generate HTML report if requested
		if s.config.HTMLOutput {
			if err := s.generateHTMLReport(results, jsonPath); err != nil {
				fmt.Printf("%sWarning: Failed to generate HTML report: %v%s\n",
					utils.ColorYellow, err, utils.ColorEnd)
			}
		}

		// After saving the file, send to Discord if webhook is configured
		if s.config.WebhookURL != "" {
			htmlPath := filepath.Join(s.config.OutputDir, "security-report.html")
			if err := s.sendToDiscord(jsonPath, htmlPath); err != nil {
				fmt.Printf("%sWarning: Failed to send results to Discord: %v%s\n",
					utils.ColorYellow, err, utils.ColorEnd)
			}
		}
	}

	return nil
}

func (s *APKScanner) generateHTMLReport(results map[string][]string, jsonPath string) error {
	// Extract package information from AndroidManifest.xml
	packageName, version := reporter.ExtractPackageInfo(s.tempDir)

	// Prepare HTML report data
	reportData := reporter.HTMLReportData{
		APKName:       filepath.Base(s.config.APKPath),
		PackageName:   packageName,
		Version:       version,
		ScanTime:      time.Now().Format("2006-01-02 15:04:05"),
		TotalFindings: s.countTotalFindings(results),
		Categories:    s.prepareCategoriesData(results),
		Summary:       s.prepareSummaryData(results),
	}

	// Generate HTML report
	htmlContent, err := reporter.GenerateHTMLReport(reportData)
	if err != nil {
		return fmt.Errorf("failed to generate HTML report: %v", err)
	}

	htmlPath := filepath.Join(s.config.OutputDir, "security-report.html")
	if err := ioutil.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("failed to write HTML report: %v", err)
	}

	fmt.Printf("%sHTML report generated: %s%s%s\n",
		utils.ColorBlue, utils.ColorGreen, htmlPath, utils.ColorEnd)
	return nil
}

func (s *APKScanner) countTotalFindings(results map[string][]string) int {
	total := 0
	for _, findings := range results {
		total += len(findings)
	}
	return total
}

func (s *APKScanner) prepareCategoriesData(results map[string][]string) map[string]reporter.CategoryData {
	categories := make(map[string]reporter.CategoryData)

	for category, findings := range results {
		if len(findings) == 0 {
			continue
		}

		var findingData []reporter.FindingData
		for _, finding := range findings {
			// Parse finding string to extract file, match, and context
			// Format: "file: match (Context: ...context...)"
			parts := strings.Split(finding, ": ")
			if len(parts) >= 2 {
				file := parts[0]
				remaining := strings.Join(parts[1:], ": ")
				match := remaining
				context := ""

				// Extract context if present
				if strings.Contains(remaining, " (Context: ") {
					contextStart := strings.Index(remaining, " (Context: ")
					context = remaining[contextStart+11 : len(remaining)-1]
					match = remaining[:contextStart]
				}

				// Clean up the context - remove extra whitespace and newlines
				context = strings.TrimSpace(context)

				// Replace common patterns with better formatting
				context = strings.ReplaceAll(context, "❯ Description:", "\n❯ Description:")
				context = strings.ReplaceAll(context, "❯ Impact:", "\n❯ Impact:")
				context = strings.ReplaceAll(context, "❯ Recommendation:", "\n❯ Recommendation:")
				context = strings.ReplaceAll(context, "❯ Files:", "\n❯ Files:")
				context = strings.ReplaceAll(context, "• ", "\n• ")
				context = strings.ReplaceAll(context, "│ ", "\n│ ")

				// Clean up extra whitespace
				context = strings.ReplaceAll(context, "\n ", "\n")
				context = strings.ReplaceAll(context, "\n\n", "\n")
				context = strings.TrimSpace(context)

				findingData = append(findingData, reporter.FindingData{
					File:    file,
					Match:   strings.TrimSpace(match),
					Context: context,
				})
			}
		}

		categories[category] = reporter.CategoryData{
			Name:     category,
			Count:    len(findings),
			Findings: findingData,
		}
	}

	return categories
}

func (s *APKScanner) prepareSummaryData(results map[string][]string) reporter.SummaryData {
	// Count files processed (this is an approximation)
	totalFiles := 0
	filepath.Walk(s.tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isRelevantFile(path) {
			totalFiles++
		}
		return nil
	})

	// Count patterns loaded
	totalPatterns := len(s.patterns)

	// Count vulnerabilities and risk levels
	vulnerabilities := 0
	highRisk := 0
	mediumRisk := 0
	lowRisk := 0

	for category, findings := range results {
		if len(findings) == 0 {
			continue
		}

		vulnerabilities += len(findings)

		// Determine risk level based on category name
		categoryLower := strings.ToLower(category)
		if strings.Contains(categoryLower, "high") || strings.Contains(categoryLower, "critical") {
			highRisk += len(findings)
		} else if strings.Contains(categoryLower, "medium") {
			mediumRisk += len(findings)
		} else {
			lowRisk += len(findings)
		}
	}

	return reporter.SummaryData{
		TotalFiles:      totalFiles,
		TotalPatterns:   totalPatterns,
		Vulnerabilities: vulnerabilities,
		HighRisk:        highRisk,
	}
}

// Helper function to filter relevant files
func isRelevantFile(filename string) bool {
	// Skip common resource and library files
	skipPaths := []string{
		"/res/anim/",
		"/res/color/",
		"/res/drawable/",
		"/res/layout/",
		"/res/menu/",
		"/res/mipmap/",
		"/res/xml/",
		"/resources/",
		"/META-INF/",
		"/kotlin/",
		"/okhttp3/",
		"/okio/",
	}

	for _, skip := range skipPaths {
		if strings.Contains(filename, skip) {
			return false
		}
	}

	// Focus on files that typically contain sensitive information
	relevantExts := []string{
		".java",       // Java source
		".kt",         // Kotlin source
		".xml",        // Configuration files
		".txt",        // Text files
		".json",       // JSON data
		".yaml",       // YAML data
		".yml",        // YAML data
		".properties", // Properties files
		".conf",       // Configuration files
		".config",     // Configuration files
		".plist",      // iOS/macOS property lists
		".db",         // Databases
		".sql",        // SQL files
		".env",        // Environment files
		".ini",        // INI configuration
		".html",       // HTML files
		".js",         // JavaScript files
		".php",        // PHP files
		".py",         // Python files
	}

	ext := strings.ToLower(filepath.Ext(filename))
	for _, relevantExt := range relevantExts {
		if ext == relevantExt {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
