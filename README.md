# apkX 🔍⏱️

Advanced APK analysis tool with intelligent caching, pattern matching, and comprehensive security vulnerability detection

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GitHub Actions](https://img.shields.io/badge/github-actions-blue.svg)
![Version](https://img.shields.io/badge/version-v2.0.0-orange.svg)

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
  - And 1600+ more patterns...

### 🛡️ **Security Vulnerability Detection**
- 🔄 **Task Hijacking**: Activity launch mode vulnerability analysis
- 🚨 **Janus Vulnerability**: APK signature scheme analysis (V1/V2/V3)
- 🔒 **Insecure Storage**: SharedPreferences and SQLite security analysis
- 🔐 **Certificate Pinning**: SSL/TLS security implementation checks
- 🐛 **Debug Mode**: Production build security validation
- 📱 **Android Manifest**: Security configuration analysis

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

## Requirements 🛠️
- Go 1.21+
- Java 8+ (for JADX)
- JADX (automatically downloaded if not found)

## Installation 📦
```bash
# Clone the repository
git clone https://github.com/cyinnove/apkX.git
cd apkX

# Build the binary
go build -o apkx cmd/apkx/main.go
```

## Usage 🚀

### **Basic Commands**
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
# Task hijacking vulnerability scan
./apkx -task-hijacking -apk target.apk

# Janus vulnerability detection
./apkx -janus -apk target.apk

# Generate HTML report
./apkx -html -apk target.apk

# Full comprehensive scan (RECOMMENDED)
./apkx -html -janus -apk target.apk
```

### **Advanced Commands**
```bash
# Send results to Discord
./apkx -wh "https://discord.com/api/webhooks/your-webhook-url" app.apk

# Full scan with custom output and workers
./apkx -html -janus -o results -w 8 -apk target.apk
```

### **Command Line Flags**
- `-apk`: Path to APK file
- `-o`: Output directory (default: "apkx-output")
- `-p`: Path to patterns file (default: "config/regexes.yaml")
- `-w`: Number of concurrent workers (default: 3)
- `-wh`: Discord webhook URL for sending results (optional)
- `-task-hijacking`: Enable task hijacking vulnerability scanning
- `-html`: Generate HTML report (default: false)
- `-janus`: Enable Janus vulnerability scanning (default: false)

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
3. Results will be sent as a file attachment with a summary message

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