package analyzer

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cyinnove/apkX/internal/utils"
)

type AndroidManifest struct {
	XMLName     xml.Name    `xml:"manifest"`
	Package     string      `xml:"package,attr"`
	Application Application `xml:"application"`
}

type Application struct {
	Activities []Activity `xml:"activity"`
}

type Activity struct {
	Name       string `xml:"name,attr"`
	LaunchMode string `xml:"http://schemas.android.com/apk/res/android launchMode,attr"`
	Exported   string `xml:"http://schemas.android.com/apk/res/android exported,attr"`
}

type TaskHijackingAnalyzer struct{}

func NewTaskHijackingAnalyzer() *TaskHijackingAnalyzer {
	return &TaskHijackingAnalyzer{}
}

func (a *TaskHijackingAnalyzer) Analyze(decompileDir string) ([]string, error) {
	manifestPaths := []string{
		filepath.Join(decompileDir, "resources", "AndroidManifest.xml"),
		filepath.Join(decompileDir, "AndroidManifest.xml"),
	}

	var manifestData []byte
	var err error

	for _, path := range manifestPaths {
		manifestData, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to read AndroidManifest.xml: %v", err)
	}

	var manifest AndroidManifest
	if err := xml.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse AndroidManifest.xml: %v", err)
	}

	var findings []string
	var vulnerableCount int

	// Add summary header
	findings = append(findings, fmt.Sprintf(`
%s╭───────────────────────────────────────────────╮
│         Task Hijacking Vulnerability Scan       │
╰───────────────────────────────────────────────╯%s
`, utils.ColorCyan, utils.ColorEnd))

	for _, activity := range manifest.Application.Activities {
		if activity.LaunchMode == "singleTask" || activity.LaunchMode == "2" {
			vulnerableCount++
			severity := "MEDIUM"
			severityColor := utils.ColorYellow
			if activity.Exported == "true" {
				severity = "HIGH"
				severityColor = utils.ColorRed
			}

			exportStatus := "non-public"
			if activity.Exported == "true" {
				exportStatus = "public"
			}

			finding := fmt.Sprintf(`
%s╭─ Vulnerable Activity #%d ─%s
│ 
│  %s[%s]%s Task Hijacking Vulnerability
│
│  Activity: %s%s%s
│  Launch Mode: singleTask
│  Exported: %s%s%s
│
│  %s❯ Description:%s
│    • Activity configured with singleTask launch mode
│    • %s risk due to %s export status
│    • Vulnerable to task hijacking attacks
│
│  %s❯ Impact:%s
│    • Malicious apps can inject activities into the task stack
│    • Potential information disclosure
│    • Possible phishing attacks through UI overlay
│
│  %s❯ Recommendation:%s
│    • Change launch mode to "standard" if possible
│    • If singleTask is required:
│      - Implement task affinity checks
│      - Use FLAG_ACTIVITY_NEW_TASK with FLAG_ACTIVITY_CLEAR_TOP
│      - Add additional security validations
│
╰────────────────────────────────────────────────`,
				utils.ColorCyan, vulnerableCount, utils.ColorEnd,
				severityColor, severity, utils.ColorEnd,
				utils.ColorBlue, activity.Name, utils.ColorEnd,
				utils.ColorBlue, activity.Exported, utils.ColorEnd,
				utils.ColorGreen, utils.ColorEnd,
				severity,
				exportStatus,
				utils.ColorGreen, utils.ColorEnd,
				utils.ColorGreen, utils.ColorEnd)
			findings = append(findings, finding)
		}
	}

	// Add summary footer
	if vulnerableCount == 0 {
		findings = append(findings, fmt.Sprintf(`
%s╭───────────────────────────────────────────────╮
│     ✓ No Task Hijacking Vulnerabilities Found   │
╰───────────────────────────────────────────────╯%s
`, utils.ColorGreen, utils.ColorEnd))
	} else {
		findings = append(findings, fmt.Sprintf(`
%s╭───────────────────────────────────────────────╮
│     ⚠ Found %d Task Hijacking Vulnerabilities   │
╰───────────────────────────────────────────────╯%s
`, utils.ColorRed, vulnerableCount, utils.ColorEnd))
	}

	return findings, nil
}
