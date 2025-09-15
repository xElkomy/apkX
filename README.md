# apkX 🔍⏱️

Advanced APK analysis tool with intelligent caching, pattern matching, comprehensive security vulnerability detection, and **web portal interface**

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GitHub Actions](https://img.shields.io/badge/github-actions-blue.svg)
![Version](https://img.shields.io/badge/version-v3.1.0-orange.svg)
[![Build and Release](https://github.com/h0tak88r/apkX/actions/workflows/build.yml/badge.svg)](https://github.com/h0tak88r/apkX/actions/workflows/build.yml)

## Features ✨

### 🔍 **Pattern-Based Analysis**
- 🎯 Intelligent pattern matching with context
- 🔍 Deep APK analysis for:
  - URIs and endpoints
  - API keys and secrets
  - Firebase configurations
  - Access tokens
  - Email addresses
  - Database connections
  - Hardcoded credentials
  - And **1652+ patterns** (including new security vulnerability patterns)...

### 🛡️ **Comprehensive Security Vulnerability Detection**
- 🔄 **Task Hijacking**: Activity launch mode vulnerability analysis (singleTask, taskAffinity)
- 🚨 **Janus Vulnerability**: APK signature scheme analysis (V1/V2/V3)
- 🔒 **Insecure Storage**: SharedPreferences and SQLite security analysis
- 🔐 **Certificate Pinning**: SSL/TLS security implementation checks
- 🐛 **Debug Mode**: Production build security validation
- 📱 **Android Manifest Analysis**:
  - **Exported Activities**: Activities accessible by other apps
  - **Exported Services**: Services vulnerable to hijacking
  - **Exported Broadcast Receivers**: Intent-based vulnerabilities
  - **Exported Content Providers**: Data exposure risks
  - **WebViews**: XSS and injection possibilities
  - **Deep Links**: Custom URL scheme vulnerabilities
  - **File Provider Exports**: File access vulnerabilities
  - **Custom URL Schemes**: All custom schemes detection

### 📊 **Reporting & Output**
- 🌐 **Beautiful HTML Reports** with interactive visualization
- 📊 Detailed JSON reports with context
- 🎨 Beautiful terminal output with progress tracking
- 📄 Pagination and context toggling in HTML reports
- 🔍 Clean, readable vulnerability descriptions

### ⚡ **Performance & Efficiency**
- 🚀 Smart caching system for faster repeated analysis
- ⚡ Concurrent file processing (multi-threaded)
- 🔄 Automatic JADX installation
- 💾 Efficient disk usage with SHA256-based caching
- 🤖 Discord webhook integration for automated notifications

### 🌐 **Web Portal Interface**
- 🖥️ **Modern Web UI**: Beautiful, responsive web interface
- 🌙 **Dark/Light Mode**: Toggle between themes with persistent preferences
- 📤 **Drag & Drop Upload**: Easy APK file upload with progress tracking
- ⬇️ **APK Download**: Download APKs by package name from multiple sources
- 🔔 **Discord Integration**: Per-upload webhook configuration
- 📊 **Report Management**: View and download all analysis reports
- 📱 **Mobile Friendly**: Responsive design works on all devices
- 🔧 **MITM Patching**: Apply HTTPS inspection patches using apk-mitm
- ⚡ **Async Processing**: Non-blocking analysis with real-time job status

## Requirements 🛠️
- Go 1.21+
- Java 8+ (for JADX)
- JADX (automatically downloaded if not found)

### System prerequisites
- unzip, zip, tar, curl, git
- Linux or macOS recommended (Windows supported via WSL)

### Optional but recommended tools
- Node.js 16+ and npm (for `apk-mitm` if you enable MITM patching)
- Python 3.8+ and pip (for `apkeep` APK downloader)

### Install external tools
```bash
# apk-mitm (MITM HTTPS patching)
npm install -g apk-mitm

# apkeep (APK download by package name)
pip install --upgrade apkeep
```

Notes:
- MITM patching is optional. If `apk-mitm` is not installed or fails, analysis continues on the original APK.
- XAPK files are supported; apkX automatically extracts the embedded APK before analysis.

## Installation 📦
```bash
# Clone the repository
git clone https://github.com/h0tak88r/apkX.git
cd apkX

# Build the CLI binary
go build -o apkx cmd/apkx/main.go

# Build the web server
go build -o apkx-web cmd/server/main.go
```

## Usage 🚀

### **🌐 Web Portal Interface (Recommended)**
```bash
# Start the web server
./apkx-web -addr :9090

# With Discord webhook (optional)
./apkx-web -addr :9090 -webhook "https://discord.com/api/webhooks/XXX/YYY"

# With MITM patching enabled
./apkx-web -addr :9090 -mitm

# Using environment variable
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/XXX/YYY"
./apkx-web -addr :9090
```

### Run with Docker
```bash
# Build image
docker build -t apkx-web .

# Run (with MITM enabled by default)
docker run --rm -p 9090:9090 apkx-web
```

### One-shot installer (Debian/Ubuntu)
```bash
bash scripts/setup.sh
```

Then open `http://localhost:9090` in your browser to:
- Upload APK files via drag & drop
- Download APKs by package name from APKPure, Google Play, F-Droid, Huawei AppGallery
- Apply MITM patches for HTTPS inspection
- Configure Discord webhooks per upload
- View and download analysis reports
- Toggle between dark/light themes
- Real-time job status tracking

### **📱 Command Line Interface**
```bash
# Basic usage
./apkx [flags] <apk-file(s)>

# Analyze multiple APKs
./apkx app1.apk app2.apk app3.apk

# Specify output directory
./apkx -o custom-output-dir app.apk

# Use custom patterns file
./apkx -p custom-patterns.yaml app.apk

# Control worker count
./apkx -w 5 app.apk
```

### **Security Analysis Commands**
```bash
# Full comprehensive scan with all security checks (RECOMMENDED)
./apkx -html -apk target.apk

# Generate HTML report with all vulnerability categories
./apkx -html -apk target.apk

# Analyze specific APK with custom output
./apkx -html -o results -apk target.apk
```

### **Advanced Commands**
```bash
# Send both JSON and HTML reports to Discord
./apkx -html -wh "https://discord.com/api/webhooks/your-webhook-url" app.apk

# Full scan with custom output and workers
./apkx -html -o results -w 8 -apk target.apk
```

### **Command Line Flags**
- `-apk`: Path to APK file
- `-o`: Output directory (default: "apkx-output")
- `-p`: Path to patterns file (default: "config/regexes.yaml")
- `-w`: Number of concurrent workers (default: 3)
- `-wh`: Discord webhook URL for sending results (optional)
- `-html`: Generate HTML report (default: false)

### **Web Server Flags**
- `-addr`: HTTP listen address (default: ":9090")
- `-webhook`: Default Discord webhook URL (optional)
- `-mitm`: Enable MITM patching for HTTPS inspection using apk-mitm
- `PORT`: Environment variable for port (e.g., `PORT=8080`)

## Security Vulnerability Detection 🛡️

### **Task Hijacking Analysis**
Detects activities vulnerable to task hijacking attacks:
- Activities with `singleTask` launch mode
- Exported activities with security implications
- Risk assessment based on export status

### **Janus Vulnerability Detection**
Analyzes APK signature schemes for Janus attack vulnerability:
- **V1 Signature**: Legacy signature scheme
- **V2 Signature**: Modern signature scheme (Android 7.0+)
- **V3 Signature**: Latest signature scheme (Android 9.0+)
- **Risk Levels**: None, Medium, High based on signature combinations

### **Insecure Storage Analysis**
Identifies insecure data storage practices:
- SharedPreferences usage without encryption
- Unencrypted SQLite databases
- Plain text data storage

### **Certificate Pinning Analysis**
Checks for SSL/TLS security implementations:
- Missing certificate pinning
- Insecure network communication
- MITM attack vulnerability

### **Debug Mode Detection**
Validates production build security:
- Debug mode enabled in production
- Security implications of debug builds

## HTML Report Features 🌐

The HTML report provides an interactive, beautiful visualization of all findings:

- **📊 Summary Dashboard**: Overview of all vulnerabilities and findings
- **🔍 Interactive Findings**: Click to expand context and details
- **📄 Pagination**: Navigate through large result sets
- **🎨 Clean Formatting**: ANSI code stripping and proper text formatting
- **📱 Responsive Design**: Works on desktop and mobile devices
- **⚡ Fast Loading**: Optimized for large reports

## Discord Integration 🤖
Send analysis results directly to your Discord channel:
1. Create a webhook in your Discord server
2. Use the `-wh` flag with your webhook URL
3. Both JSON and HTML reports will be sent as file attachments with a summary message
4. JSON report for programmatic access and HTML report for human-readable visualization

## Cache Management 💾
APK decompilations are cached in `~/.apkx/cache/` for faster repeated analysis:
```bash
# Clear entire cache
rm -rf ~/.apkx/cache/

# View cache contents
ls -la ~/.apkx/cache/
```

## Output Format 📝

### **JSON Output**
Results are saved in JSON format with:
- File paths relative to APK root
- Match context (surrounding code)
- Pattern categories
- Vulnerability details

### **HTML Output**
Interactive web-based reports with:
- Categorized findings
- Context toggling
- Pagination controls
- Clean, readable formatting

Example JSON output:
```json
{
  "api_keys": [
    "path/to/file.java: API_KEY_123 (Context: ...surrounding code...)"
  ],
  "urls": [
    "path/to/config.xml: https://api.example.com (Context: ...surrounding code...)"
  ],
  "TaskHijacking": [
    "Activity: com.example.VulnerableActivity (Launch Mode: singleTask, Exported: true)"
  ],
  "JanusVulnerability": [
    "V1 Signature: true, V2 Signature: true, V3 Signature: false - Medium Risk"
  ]
}
```

## Changelog 📝

### **v3.1.0** - Comprehensive Android Security Analysis
- 🛡️ **NEW**: Complete Android Manifest security analysis
  - **Exported Activities**: Detect activities accessible by other apps
  - **Exported Services**: Identify services vulnerable to hijacking
  - **Exported Broadcast Receivers**: Find intent-based vulnerabilities
  - **Exported Content Providers**: Detect data exposure risks
  - **WebViews**: Identify XSS and injection possibilities
  - **Deep Links**: Find custom URL scheme vulnerabilities
  - **File Provider Exports**: Detect file access vulnerabilities
  - **Custom URL Schemes**: Comprehensive scheme detection
- 🔄 **NEW**: Enhanced Task Hijacking detection with regex-based patterns
  - **taskAffinity**: Detect activities with custom task affinity
  - **SingleTask Launch Mode**: Identify singleTask launch mode vulnerabilities
- 🔒 **NEW**: Security vulnerability patterns integrated into main analyzer
  - **InsecureStorage**: SharedPreferences and SQLite security analysis
  - **CertificatePinning**: SSL/TLS security implementation checks
  - **DebugMode**: Production build security validation
- 📊 **IMPROVED**: Enhanced HTML reports with modern design
  - **Consolidated summary section** - No more redundant information
  - **Icon-based cards** with better visual hierarchy
  - **Improved color scheme** and typography
  - **Better responsive design** for all devices
- ⚡ **IMPROVED**: Performance optimizations
  - **1652+ patterns** loaded for comprehensive scanning
  - **Regex-based detection** for all security vulnerabilities
  - **Simplified output format** for better readability
- 🧹 **CLEANUP**: Removed deprecated analyzers and consolidated codebase

### **v3.0.0** - Advanced Web Portal & MITM Integration
- 🔧 **NEW**: MITM patching integration using apk-mitm for HTTPS inspection
- ⬇️ **NEW**: APK download functionality from multiple sources (APKPure, Google Play, F-Droid, Huawei AppGallery)
- ⚡ **NEW**: Asynchronous job processing with real-time status updates
- 🎯 **NEW**: Smart download system - serves patched APK when MITM enabled, original otherwise
- 📊 **NEW**: Package name and version extraction in HTML reports
- 🔄 **NEW**: Job management system with active job tracking
- 🗑️ **NEW**: Report deletion functionality
- 🎨 **IMPROVED**: Enhanced UI with tabbed interface for upload/download
- 🔧 **IMPROVED**: Better error handling and user feedback
- 🛠️ **IMPROVED**: Analysis now uses original APK while keeping patched version for download

### **v2.1.0** - Web Portal Release
- 🌐 **NEW**: Web portal interface with modern UI
- 🌙 **NEW**: Dark/Light mode toggle with persistent preferences
- 📤 **NEW**: Drag & drop APK upload functionality
- 🔔 **NEW**: Per-upload Discord webhook configuration
- 📊 **NEW**: Web-based report management and viewing
- 📱 **NEW**: Responsive design for mobile devices
- ⚡ **NEW**: Web server with configurable port and webhook defaults
- 🎨 **IMPROVED**: Enhanced UI/UX with smooth animations
- 🔧 **IMPROVED**: Better error handling and user feedback

### **v2.0.0** - Major Update
- ✨ Added HTML report generation with interactive visualization
- 🚨 Implemented Janus vulnerability detection
- 🔒 Added comprehensive security vulnerability checks
- 📄 Added pagination and context toggling in HTML reports
- 🎨 Improved readability with ANSI code stripping
- 🔧 Fixed task hijacking count accuracy
- 🗑️ Removed duplicate hardcoded credentials scanning
- 📊 Enhanced reporting with better categorization

### **v1.x.x** - Previous Versions
- Pattern-based analysis
- JSON output
- Basic caching system
- Task hijacking detection

## Contributing 🤝
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License 📄
MIT License - see [LICENSE](LICENSE) for details

---

🔧 Maintained by [h0tak88r](https://github.com/h0tak88r)
🔧 Maintained by [h0tak88r](https://github.com/h0tak88r)