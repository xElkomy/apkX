package main

import (
	"flag"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/apkX/internal/analyzer"
)

const (
	uploadDir   = "/home/sallam/AutoAR/apkX/web-data/uploads"
	reportsRoot = "/home/sallam/AutoAR/apkX/web-data/reports"
)

// Optional global Discord webhook to forward results (JSON + HTML)
var serverDefaultWebhook string

func main() {
	must(os.MkdirAll(uploadDir, 0755))
	must(os.MkdirAll(reportsRoot, 0755))

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/upload", handleUpload)

	// Serve reports statically
	fs := http.FileServer(http.Dir(reportsRoot))
	http.Handle("/reports/", http.StripPrefix("/reports/", fs))

	// Address selection: PORT env or default 9090; can override with -addr
	defaultAddr := ":" + getEnv("PORT", "9090")
	addr := flag.String("addr", defaultAddr, "HTTP listen address, e.g. :9090 or 127.0.0.1:9090")
	webhook := flag.String("webhook", getEnv("DISCORD_WEBHOOK", ""), "Discord webhook URL to send results (JSON + HTML)")
	flag.Parse()

	serverDefaultWebhook = *webhook

	log.Printf("apkX web server listening on %s (set PORT env or -addr to change)", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>apkX Web</title>
  <style>
    :root {
      --bg-primary: #1a1a1a;
      --bg-secondary: #2d2d2d;
      --bg-tertiary: #3a3a3a;
      --text-primary: #ffffff;
      --text-secondary: #b0b0b0;
      --text-muted: #808080;
      --accent-primary: #00d4ff;
      --accent-secondary: #0099cc;
      --border-color: #404040;
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }
    
    [data-theme="light"] {
      --bg-primary: #ffffff;
      --bg-secondary: #f8f9fa;
      --bg-tertiary: #e9ecef;
      --text-primary: #212529;
      --text-secondary: #6c757d;
      --text-muted: #adb5bd;
      --accent-primary: #007bff;
      --accent-secondary: #0056b3;
      --border-color: #dee2e6;
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      line-height: 1.6;
      color: var(--text-primary);
      background: var(--bg-primary);
      min-height: 100vh;
      transition: all 0.3s ease;
    }
    
    .header {
      background: var(--bg-secondary);
      padding: 20px 40px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--shadow);
    }
    
    .header h1 {
      color: var(--accent-primary);
      font-size: 2em;
      font-weight: 700;
    }
    
    .theme-toggle {
      background: var(--accent-primary);
      color: var(--bg-primary);
      border: none;
      padding: 10px 20px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.3s ease;
    }
    
    .theme-toggle:hover {
      background: var(--accent-secondary);
      transform: translateY(-2px);
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 40px;
    }
    
    .card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      padding: 24px;
      border-radius: 12px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
      transition: all 0.3s ease;
    }
    
    .card:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.2);
    }
    
    .card h2 {
      color: var(--accent-primary);
      margin-bottom: 20px;
      font-size: 1.5em;
      font-weight: 600;
    }
    
    .form-group {
      margin-bottom: 20px;
    }
    
    .form-group label {
      display: block;
      margin-bottom: 8px;
      color: var(--text-primary);
      font-weight: 500;
    }
    
    .form-group input[type="file"] {
      width: 100%;
      padding: 12px;
      border: 2px dashed var(--border-color);
      border-radius: 8px;
      background: var(--bg-tertiary);
      color: var(--text-primary);
      cursor: pointer;
      transition: all 0.3s ease;
    }
    
    .form-group input[type="file"]:hover {
      border-color: var(--accent-primary);
      background: var(--bg-primary);
    }
    
    .form-group input[type="text"] {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      background: var(--bg-tertiary);
      color: var(--text-primary);
      font-size: 14px;
      transition: all 0.3s ease;
    }
    
    .form-group input[type="text"]:focus {
      outline: none;
      border-color: var(--accent-primary);
      box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
    }
    
    .form-group input[type="text"]::placeholder {
      color: var(--text-muted);
    }
    
    .checkbox-group {
      display: flex;
      align-items: center;
      margin-bottom: 15px;
    }
    
    .checkbox-group input[type="checkbox"] {
      margin-right: 10px;
      transform: scale(1.2);
    }
    
    .checkbox-group label {
      margin-bottom: 0;
      cursor: pointer;
      user-select: none;
    }
    
    .btn {
      background: var(--accent-primary);
      color: var(--bg-primary);
      border: none;
      padding: 12px 24px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      font-size: 16px;
      transition: all 0.3s ease;
      width: 100%;
    }
    
    .btn:hover {
      background: var(--accent-secondary);
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
    }
    
    .btn:active {
      transform: translateY(0);
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border-color);
    }
    
    th {
      background: var(--bg-tertiary);
      color: var(--accent-primary);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.9em;
      letter-spacing: 0.5px;
    }
    
    td {
      color: var(--text-primary);
    }
    
    a {
      color: var(--accent-primary);
      text-decoration: none;
      font-weight: 500;
      transition: color 0.3s ease;
    }
    
    a:hover {
      color: var(--accent-secondary);
      text-decoration: underline;
    }
    
    .webhook-section {
      background: var(--bg-tertiary);
      padding: 16px;
      border-radius: 8px;
      margin-top: 15px;
      border-left: 4px solid var(--accent-primary);
    }
    
    .webhook-section.hidden {
      display: none;
    }
    
    .small-text {
      font-size: 0.85em;
      color: var(--text-muted);
      margin-top: 8px;
    }
    
    .no-reports {
      text-align: center;
      padding: 40px;
      color: var(--text-muted);
      font-style: italic;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔍 apkX Web Portal</h1>
    <button class="theme-toggle" onclick="toggleTheme()">🌙 Dark Mode</button>
  </div>
  
  <div class="container">
    <div class="card">
      <h2>Upload APK</h2>
      <form action="/upload" method="post" enctype="multipart/form-data">
        <div class="form-group">
          <label for="apk">Select APK File</label>
          <input type="file" name="apk" id="apk" accept=".apk" required>
        </div>
        
        <div class="checkbox-group">
          <input type="checkbox" name="html" id="html" checked>
          <label for="html">Generate HTML report</label>
        </div>
        
        <div class="checkbox-group">
          <input type="checkbox" name="send_discord" id="discordCheckbox" onchange="toggleWebhookSection()">
          <label for="discordCheckbox">Send to Discord</label>
        </div>
        
        <div class="webhook-section hidden" id="webhookSection">
          <div class="form-group">
            <label for="webhook">Discord Webhook URL</label>
            <input type="text" name="webhook" id="webhook" placeholder="https://discord.com/api/webhooks/...">
            <div class="small-text">Server default: {{.DefaultWebhookHint}}</div>
          </div>
        </div>
        
        <button class="btn" type="submit">🚀 Analyze APK</button>
      </form>
    </div>
    
    <div class="card">
      <h2>📊 Analysis Reports</h2>
      {{if .Rows}}
      <table>
        <thead>
          <tr>
            <th>APK</th>
            <th>Time</th>
            <th>JSON</th>
            <th>HTML</th>
          </tr>
        </thead>
        <tbody>
          {{range .Rows}}
          <tr>
            <td>{{.APK}}</td>
            <td>{{.When}}</td>
            <td>{{if .JSON}}<a href="/reports/{{.ID}}/results.json">📄 results.json</a>{{end}}</td>
            <td>{{if .HTML}}<a href="/reports/{{.ID}}/security-report.html">🌐 security-report.html</a>{{end}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <div class="no-reports">
        <p>No analysis reports yet. Upload an APK to get started!</p>
      </div>
      {{end}}
    </div>
  </div>
  
  <script>
    // Theme management
    function toggleTheme() {
      const body = document.body;
      const themeToggle = document.querySelector('.theme-toggle');
      const currentTheme = body.getAttribute('data-theme');
      
      if (currentTheme === 'light') {
        body.setAttribute('data-theme', 'dark');
        themeToggle.textContent = '🌙 Dark Mode';
        localStorage.setItem('theme', 'dark');
      } else {
        body.setAttribute('data-theme', 'light');
        themeToggle.textContent = '☀️ Light Mode';
        localStorage.setItem('theme', 'light');
      }
    }
    
    // Load saved theme
    function loadTheme() {
      const savedTheme = localStorage.getItem('theme') || 'dark';
      const body = document.body;
      const themeToggle = document.querySelector('.theme-toggle');
      
      body.setAttribute('data-theme', savedTheme);
      themeToggle.textContent = savedTheme === 'light' ? '☀️ Light Mode' : '🌙 Dark Mode';
    }
    
    // Webhook section toggle
    function toggleWebhookSection() {
      const checkbox = document.getElementById('discordCheckbox');
      const section = document.getElementById('webhookSection');
      const webhookInput = document.getElementById('webhook');
      
      if (checkbox.checked) {
        section.classList.remove('hidden');
        webhookInput.focus();
      } else {
        section.classList.add('hidden');
        webhookInput.value = '';
      }
    }
    
    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
      loadTheme();
      
      // Check if Discord checkbox should be checked (if webhook is provided)
      const webhookInput = document.getElementById('webhook');
      if (webhookInput.value) {
        document.getElementById('discordCheckbox').checked = true;
        toggleWebhookSection();
      }
    });
  </script>
</body>
</html>`))

type reportRow struct {
	ID   string
	APK  string
	When string
	JSON bool
	HTML bool
}

type indexData struct {
	Rows               []reportRow
	DefaultWebhookHint string
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	rows := listReports()
	data := indexData{Rows: rows, DefaultWebhookHint: "configured"}
	if err := indexTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func listReports() []reportRow {
	entries, err := os.ReadDir(reportsRoot)
	if err != nil {
		return nil
	}
	var rows []reportRow
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		metaPath := filepath.Join(reportsRoot, id, "apk.name")
		apkName := readString(metaPath)
		st, _ := os.Stat(filepath.Join(reportsRoot, id))
		row := reportRow{
			ID:   id,
			APK:  apkName,
			When: st.ModTime().Format("2006-01-02 15:04:05"),
			JSON: fileExists(filepath.Join(reportsRoot, id, "results.json")),
			HTML: fileExists(filepath.Join(reportsRoot, id, "security-report.html")),
		}
		rows = append(rows, row)
	}
	// Newest first
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, header, err := r.FormFile("apk")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate extension
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".apk") {
		http.Error(w, "only .apk files are allowed", http.StatusBadRequest)
		return
	}

	// Save upload
	savedPath, err := saveUploadedFile(file, header)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create report directory
	runID := time.Now().Format("20060102-150405")
	outDir := filepath.Join(reportsRoot, runID)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Write simple meta
	_ = os.WriteFile(filepath.Join(outDir, "apk.name"), []byte(filepath.Base(savedPath)), 0644)

	// Run analyzer
	generateHTML := r.FormValue("html") != ""
	sendDiscord := r.FormValue("send_discord") != ""
	webhookURL := strings.TrimSpace(r.FormValue("webhook"))

	// Use form webhook if provided, otherwise use server default
	if sendDiscord {
		if webhookURL == "" {
			webhookURL = serverDefaultWebhook
		}
	} else {
		webhookURL = ""
	}

	cfg := analyzer.Config{
		APKPath:      savedPath,
		OutputDir:    outDir,
		PatternsPath: filepath.Join("/home/sallam/AutoAR/apkX", "config", "regexes.yaml"),
		Workers:      3,
		HTMLOutput:   generateHTML,
		WebhookURL:   webhookURL,
	}
	scanner := analyzer.NewAPKScanner(&cfg)
	if err := scanner.Run(); err != nil {
		log.Printf("analyze error: %v", err)
		http.Error(w, "analysis failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func saveUploadedFile(file multipart.File, header *multipart.FileHeader) (string, error) {
	dst := filepath.Join(uploadDir, safeName(header.Filename))
	out, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		return "", err
	}
	return dst, nil
}

func safeName(name string) string {
	name = filepath.Base(name)
	repl := strings.NewReplacer(" ", "-", "..", ".", "/", "-", "\\", "-")
	name = repl.Replace(name)
	return name
}

func readString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func getEnv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}
