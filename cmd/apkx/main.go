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
	version = "v1.1.0" // Updated version with Discord webhook feature
)

func printBanner() {
	fmt.Printf("\033[1;36m\n📅 Started at: %s\033[0m\n\n", time.Now().Format("2006-01-02 15:04:05"))
	banner := `         
	┌─┐┌─┐┬┌─═╗ ╦
	├─┤├─┘├┴┐╔╩╦╝
	┴ ┴┴  ┴ ┴╩ ╚═ by: h0tak88r
            				
`
	fmt.Printf("%s%s%s\n", utils.ColorHeader, banner, utils.ColorEnd)
	fmt.Printf(" Version: %s\n", version)  // Add version display
	fmt.Println(" --")
	fmt.Println(" Scanning APK file for URIs, endpoints & secrets")
	fmt.Println()
}

func main() {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Round(time.Second)
		fmt.Printf("\n%s🕒 Tool runtime: %s%s\n", utils.ColorBlue, duration, utils.ColorEnd)
	}()

	// Define flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <apk-file>\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	webhook := flag.String("wh", "", "Discord webhook URL to send results")
	outputDir := flag.String("o", "apkx-output", "Output directory for results")
	patternsFile := flag.String("p", "config/regexes.yaml", "Path to patterns file")
	workers := flag.Int("w", 3, "Number of concurrent workers")

	// Parse flags
	flag.Parse()

	// Get remaining arguments as APK files
	apkFiles := flag.Args()

	// Validate we have at least one APK file
	if len(apkFiles) == 0 {
		fmt.Printf("%sError: No APK files specified%s\n", utils.ColorRed, utils.ColorEnd)
		flag.Usage()
		os.Exit(1)
	}

	printBanner()

	// Create output directory
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Printf("%sError creating output directory: %v%s\n", utils.ColorRed, err, utils.ColorEnd)
		os.Exit(1)
	}

	// Create work channel and wait group
	jobs := make(chan string, len(apkFiles))
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(i, jobs, &wg, *outputDir, *patternsFile, *webhook)
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

func worker(id int, jobs <-chan string, wg *sync.WaitGroup, outputDir, patternsFile, webhook string) {
	defer wg.Done()

	for apkFile := range jobs {
		fmt.Printf("%s[Worker %d] Processing: %s%s\n", utils.ColorCyan, id, filepath.Base(apkFile), utils.ColorEnd)
		
		// Create output file path based on APK name
		baseName := filepath.Base(apkFile)
		nameWithoutExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))
		// Clean the filename to avoid special characters
		cleanName := cleanFileName(nameWithoutExt)
		outputFile := filepath.Join(outputDir, cleanName+"-apkx.json")

		config := analyzer.Config{
			APKFile:      apkFile,
			OutputFile:   outputFile,
			PatternsFile: patternsFile,
			Webhook:      webhook,
		}

		scanner := analyzer.NewAPKScanner(&config)
		if err := scanner.Run(); err != nil {
			fmt.Printf("%s[Worker %d] Error processing %s: %v%s\n", 
				utils.ColorRed, id, filepath.Base(apkFile), err, utils.ColorEnd)
			continue
		}

		if absPath, err := filepath.Abs(outputFile); err == nil {
			fmt.Printf("%s[Worker %d] Results saved to: %s%s\n", 
				utils.ColorGreen, id, absPath, utils.ColorEnd)
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
