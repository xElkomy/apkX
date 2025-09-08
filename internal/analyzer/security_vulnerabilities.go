package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/h0tak88r/apkX/internal/utils"
)

// InsecureStorageAnalyzer checks for insecure storage practices
type InsecureStorageAnalyzer struct{}

func NewInsecureStorageAnalyzer() *InsecureStorageAnalyzer {
	return &InsecureStorageAnalyzer{}
}

func (a *InsecureStorageAnalyzer) SetAPKPath(apkPath string) {
	// Not needed for insecure storage analyzer
}

func (a *InsecureStorageAnalyzer) Analyze(decompileDir string) ([]string, error) {
	var findings []string

	// Check for SharedPreferences usage
	sharedPrefsFindings := a.checkSharedPreferences(decompileDir)
	findings = append(findings, sharedPrefsFindings...)

	// Check for SQLite without encryption
	sqliteFindings := a.checkSQLiteEncryption(decompileDir)
	findings = append(findings, sqliteFindings...)

	return findings, nil
}

func (a *InsecureStorageAnalyzer) checkSharedPreferences(decompileDir string) []string {
	var findings []string

	// Look for SharedPreferences usage patterns
	patterns := []string{
		`SharedPreferences\.getSharedPreferences\(`,
		`getSharedPreferences\(`,
		`MODE_WORLD_READABLE`,
		`MODE_WORLD_WRITEABLE`,
	}

	for _, pattern := range patterns {
		matches := a.searchInFiles(decompileDir, pattern)
		if len(matches) > 0 {
			findings = append(findings, fmt.Sprintf(`
%s╭─ Insecure Storage: SharedPreferences ─%s
│
│  %s[LOW]%s SharedPreferences Usage Detected
│
│  %s❯ Description:%s
│    • SharedPreferences data is stored in plain text
│    • No encryption applied to sensitive data
│    • Data accessible to other apps with root access
│
│  %s❯ Files:%s
%s
╰────────────────────────────────────────────────`,
				utils.ColorCyan, utils.ColorEnd,
				utils.ColorYellow, utils.ColorEnd,
				utils.ColorGreen, utils.ColorEnd,
				utils.ColorBlue, utils.ColorEnd,
				strings.Join(matches, "\n")))
		}
	}

	return findings
}

func (a *InsecureStorageAnalyzer) checkSQLiteEncryption(decompileDir string) []string {
	var findings []string

	// Look for SQLite usage without encryption
	patterns := []string{
		`SQLiteDatabase\.openDatabase\(`,
		`SQLiteOpenHelper`,
		`CREATE TABLE`,
		`INSERT INTO`,
	}

	matches := a.searchInFiles(decompileDir, strings.Join(patterns, "|"))
	if len(matches) > 0 {
		// Check if encryption is used
		encryptionPatterns := []string{
			`SQLCipher`,
			`encrypt`,
			`decrypt`,
			`Cipher`,
		}

		hasEncryption := false
		for _, pattern := range encryptionPatterns {
			if len(a.searchInFiles(decompileDir, pattern)) > 0 {
				hasEncryption = true
				break
			}
		}

		if !hasEncryption {
			findings = append(findings, fmt.Sprintf(`
%s╭─ Insecure Storage: Unencrypted SQLite ─%s
│
│  %s[MEDIUM]%s Unencrypted Database Usage
│
│  %s❯ Description:%s
│    • SQLite database without encryption detected
│    • Sensitive data stored in plain text
│    • Database files accessible with root access
│
╰────────────────────────────────────────────────`,
				utils.ColorCyan, utils.ColorEnd,
				utils.ColorYellow, utils.ColorEnd,
				utils.ColorGreen, utils.ColorEnd))
		}
	}

	return findings
}

// CertificatePinningAnalyzer checks for certificate pinning implementation
type CertificatePinningAnalyzer struct{}

func NewCertificatePinningAnalyzer() *CertificatePinningAnalyzer {
	return &CertificatePinningAnalyzer{}
}

func (a *CertificatePinningAnalyzer) SetAPKPath(apkPath string) {
	// Not needed for certificate pinning analyzer
}

func (a *CertificatePinningAnalyzer) Analyze(decompileDir string) ([]string, error) {
	var findings []string

	// Check for certificate pinning implementation
	pinningPatterns := []string{
		`CertificatePinner`,
		`TrustManager`,
		`X509TrustManager`,
		`OkHttpClient\.Builder\(\)\.certificatePinner`,
		`SSLSocketFactory`,
		`TrustManagerFactory`,
	}

	hasPinning := false
	for _, pattern := range pinningPatterns {
		if len(a.searchInFiles(decompileDir, pattern)) > 0 {
			hasPinning = true
			break
		}
	}

	if !hasPinning {
		findings = append(findings, fmt.Sprintf(`
%s╭─ Missing Certificate Pinning ─%s
│
│  %s[MEDIUM]%s No Certificate Pinning Detected
│
│  %s❯ Description:%s
│    • No certificate pinning implementation found
│    • App vulnerable to man-in-the-middle attacks
│    • SSL/TLS connections not properly secured
│
╰────────────────────────────────────────────────`,
			utils.ColorCyan, utils.ColorEnd,
			utils.ColorYellow, utils.ColorEnd,
			utils.ColorGreen, utils.ColorEnd))
	}

	return findings, nil
}

// DebugModeAnalyzer checks for debug mode vulnerabilities
type DebugModeAnalyzer struct{}

func NewDebugModeAnalyzer() *DebugModeAnalyzer {
	return &DebugModeAnalyzer{}
}

func (a *DebugModeAnalyzer) SetAPKPath(apkPath string) {
	// Not needed for debug mode analyzer
}

func (a *DebugModeAnalyzer) Analyze(decompileDir string) ([]string, error) {
	var findings []string

	// Check AndroidManifest.xml for debug mode
	manifestPath := filepath.Join(decompileDir, "resources", "AndroidManifest.xml")
	if _, err := os.Stat(manifestPath); err == nil {
		content, err := os.ReadFile(manifestPath)
		if err == nil {
			if strings.Contains(string(content), `android:debuggable="true"`) {
				findings = append(findings, fmt.Sprintf(`
%s╭─ Debug Mode Enabled ─%s
│
│  %s[HIGH]%s Debug Mode Enabled in Production
│
│  %s❯ Description:%s
│    • android:debuggable="true" found in AndroidManifest.xml
│    • App allows debugging in production build
│    • High security risk for production apps
│
╰────────────────────────────────────────────────`,
					utils.ColorCyan, utils.ColorEnd,
					utils.ColorRed, utils.ColorEnd,
					utils.ColorGreen, utils.ColorEnd))
			}
		}
	}

	return findings, nil
}

// Helper function to search for patterns in files
func (a *InsecureStorageAnalyzer) searchInFiles(decompileDir string, pattern string) []string {
	var matches []string
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return matches
	}

	filepath.Walk(decompileDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() && isRelevantFile(path) {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			fileMatches := regex.FindAllString(string(content), -1)
			for _, match := range fileMatches {
				relPath, _ := filepath.Rel(decompileDir, path)
				matches = append(matches, fmt.Sprintf("    %s: %s", relPath, match))
			}
		}
		return nil
	})

	return matches
}

// Helper function to search for patterns in files (for other analyzers)
func (a *CertificatePinningAnalyzer) searchInFiles(decompileDir string, pattern string) []string {
	var matches []string
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return matches
	}

	filepath.Walk(decompileDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() && isRelevantFile(path) {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			fileMatches := regex.FindAllString(string(content), -1)
			for _, match := range fileMatches {
				relPath, _ := filepath.Rel(decompileDir, path)
				matches = append(matches, fmt.Sprintf("    %s: %s", relPath, match))
			}
		}
		return nil
	})

	return matches
}
