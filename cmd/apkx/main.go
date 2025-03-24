package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cyinnove/apkX/internal/analyzer"
	"github.com/cyinnove/apkX/internal/utils"
)

const (
	version = "v1.4.0" // Added Discord webhook integration
)

func printBanner() {
	fmt.Printf("\033[1;36m\n📅 Started at: %s\033[0m\n\n", time.Now().Format("2006-01-02 15:04:05"))
	banner := `         
	┌─┐┌─┐┬┌─═╗ ╦
	├─┤├─┘├┴┐╔╩╦╝
	┴ ┴┴  ┴ ┴╩ ╚═ by: h0tak88r
            				
`
	fmt.Printf("%s%s%s\n", utils.ColorHeader, banner, utils.ColorEnd)
	fmt.Printf(" Version: %s\n", version) // Add version display
	fmt.Println(" --")
	fmt.Println(" Scanning APK file for URIs, endpoints, secrets & security vulnerabilities")
	fmt.Println()
}

func main() {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Round(time.Second)
		fmt.Printf("\n%s🕒 Tool runtime: %s%s\n", utils.ColorBlue, duration, utils.ColorEnd)
	}()

	var (
		apkPath       string
		outputDir     string
		patternsPath  string
		workers       int
		webhookURL    string
		taskHijacking bool
	)

	flag.StringVar(&apkPath, "apk", "", "Path to APK file")
	flag.StringVar(&outputDir, "o", "apkx-output", "Output directory for results")
	flag.StringVar(&patternsPath, "p", "config/regexes.yaml", "Path to patterns file")
	flag.IntVar(&workers, "w", 3, "Number of concurrent workers")
	flag.StringVar(&webhookURL, "wh", "", "Discord webhook URL to send results")
	flag.BoolVar(&taskHijacking, "task-hijacking", false, "Only scan for task hijacking vulnerabilities")
	flag.Parse()

	// Get remaining arguments as APK files
	apkFiles := flag.Args()

	// If no additional args but apkPath is set, use that
	if len(apkFiles) == 0 && apkPath != "" {
		apkFiles = []string{apkPath}
	}

	// Validate we have at least one APK file
	if len(apkFiles) == 0 {
		fmt.Printf("%sError: No APK files specified%s\n", utils.ColorRed, utils.ColorEnd)
		flag.Usage()
		os.Exit(1)
	}

	printBanner()

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("%sError creating output directory: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
		os.Exit(1)
	}

	// Create work channel and wait group
	jobs := make(chan string, len(apkFiles))
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(i, jobs, &wg, outputDir, patternsPath, webhookURL, taskHijacking)
	}

	// Queue jobs
	for _, apk := range apkFiles {
		if _, err := os.Stat(apk); os.IsNotExist(err) {
			fmt.Printf("%sWarning: APK file not found: %s%s\n", utils.ColorYellow, apk, utils.ColorEnd)
			continue
		}
		jobs <- apk
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()
}

func worker(id int, jobs <-chan string, wg *sync.WaitGroup, outputDir, patternsPath, webhookURL string, taskHijacking bool) {
	defer wg.Done()

	for apkFile := range jobs {
		fmt.Printf("\n%s╭─ Worker %d ─╮%s\n", utils.ColorCyan, id, utils.ColorEnd)
		fmt.Printf("%s│ Processing: %s%s\n", utils.ColorCyan, filepath.Base(apkFile), utils.ColorEnd)
		fmt.Printf("%s╰───────────╯%s\n", utils.ColorCyan, utils.ColorEnd)

		// Create output file path based on APK name
		baseName := filepath.Base(apkFile)
		nameWithoutExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))
		cleanName := cleanFileName(nameWithoutExt)
		outputFile := filepath.Join(outputDir, cleanName+"-apkx.json")

		config := analyzer.Config{
			APKPath:        apkFile,
			OutputDir:      outputDir,
			PatternsPath:   patternsPath,
			Workers:        id + 1,
			WebhookURL:     webhookURL,
			TaskHijackOnly: taskHijacking,
		}

		scanner := analyzer.NewAPKScanner(&config)
		if err := scanner.Run(); err != nil {
			fmt.Printf("\n%s╭─ Error ─╮%s\n", utils.ColorRed, utils.ColorEnd)
			fmt.Printf("%s│ Worker %d: Failed to process %s%s\n",
				utils.ColorRed, id, filepath.Base(apkFile), utils.ColorEnd)
			fmt.Printf("%s│ Error: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
			fmt.Printf("%s╰─────────╯%s\n", utils.ColorRed, utils.ColorEnd)
			continue
		}

		if absPath, err := filepath.Abs(outputFile); err == nil {
			fmt.Printf("\n%s╭─ Success ─╮%s\n", utils.ColorGreen, utils.ColorEnd)
			fmt.Printf("%s│ Results saved to: %s%s\n",
				utils.ColorGreen, absPath, utils.ColorEnd)
			fmt.Printf("%s╰───────────╯%s\n", utils.ColorGreen, utils.ColorEnd)
		}
	}
}

// Helper function to clean filenames
func cleanFileName(name string) string {
	// Replace special characters and spaces
	replacer := strings.NewReplacer(
		" ", "-",
		":", "-",
		"/", "-",
		"\\", "-",
		"*", "",
		"?", "",
		"\"", "",
		"<", "",
		">", "",
		"|", "",
		".", "-",
	)
	cleaned := replacer.Replace(name)

	// Remove any double dashes
	for strings.Contains(cleaned, "--") {
		cleaned = strings.ReplaceAll(cleaned, "--", "-")
	}

	// Trim dashes from start and end
	cleaned = strings.Trim(cleaned, "-")

	return cleaned
}
