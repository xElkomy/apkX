package analyzer

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func (a *TaskHijackingAnalyzer) SetAPKPath(apkPath string) {
	// Not needed for task hijacking analyzer
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
	var vulnerableActivities []string

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

			activityInfo := fmt.Sprintf(`
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
╰────────────────────────────────────────────────`,
				utils.ColorCyan, vulnerableCount, utils.ColorEnd,
				severityColor, severity, utils.ColorEnd,
				utils.ColorBlue, activity.Name, utils.ColorEnd,
				utils.ColorBlue, activity.Exported, utils.ColorEnd,
				utils.ColorGreen, utils.ColorEnd,
				severity,
				exportStatus,
				utils.ColorGreen, utils.ColorEnd)
			vulnerableActivities = append(vulnerableActivities, activityInfo)
		}
	}

	// Create a single finding with all information
	if vulnerableCount == 0 {
		findings = append(findings, fmt.Sprintf(`
%s╭───────────────────────────────────────────────╮
│         Task Hijacking Vulnerability Scan       │
╰───────────────────────────────────────────────╯%s

%s╭───────────────────────────────────────────────╮
│     ✓ No Task Hijacking Vulnerabilities Found   │
╰───────────────────────────────────────────────╯%s
`, utils.ColorCyan, utils.ColorEnd, utils.ColorGreen, utils.ColorEnd))
	} else {
		// Combine all activities into a single finding
		combinedFinding := fmt.Sprintf(`
%s╭───────────────────────────────────────────────╮
│         Task Hijacking Vulnerability Scan       │
╰───────────────────────────────────────────────╯%s
%s
%s╭───────────────────────────────────────────────╮
│     ⚠ Found %d Task Hijacking Vulnerabilities   │
╰───────────────────────────────────────────────╯%s
`, utils.ColorCyan, utils.ColorEnd,
			strings.Join(vulnerableActivities, "\n"),
			utils.ColorRed, vulnerableCount, utils.ColorEnd)
		findings = append(findings, combinedFinding)
	}

	return findings, nil
}
