# apkX 🔍⏱️

Advanced APK analysis tool with intelligent caching and pattern matching for security analysis

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GitHub Actions](https://img.shields.io/github/actions/workflow/status/cyinnove/apkX/build.yml)

## Features ✨
- 🚀 Smart caching system for faster repeated analysis
- 🎯 Intelligent pattern matching with context
- 🔍 Deep APK analysis for:
  - URIs and endpoints
  - API keys and secrets
  - Firebase configurations
  - Access tokens
  - Email addresses
  - And more...
- 📊 Detailed JSON reports with context
- 🎨 Beautiful terminal output with progress tracking
- ⚡ Concurrent file processing
- 🔄 Automatic JADX installation
- 💾 Efficient disk usage with SHA256-based caching

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

### Flags
- `-o`: Output directory (default: "apkx-output")
- `-p`: Path to patterns file (default: "config/regexes.yaml")
- `-w`: Number of concurrent workers (default: 3)

## Cache Management 💾
APK decompilations are cached in `~/.apkx/cache/` for faster repeated analysis:
```bash
# Clear entire cache
rm -rf ~/.apkx/cache/

# View cache contents
ls -la ~/.apkx/cache/
```

## Output Format 📝
Results are saved in JSON format with:
- File paths relative to APK root
- Match context (surrounding code)
- Pattern categories
- Match confidence levels

Example output:
```json
{
  "api_keys": [
    "path/to/file.java: API_KEY_123 (Context: ...surrounding code...)"
  ],
  "urls": [
    "path/to/config.xml: https://api.example.com (Context: ...surrounding code...)"
  ]
}
```

## Contributing 🤝
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License 📄
MIT License - see [LICENSE](LICENSE) for details

---

🔧 Maintained by [Cyinnove](https://github.com/cyinnove) | 📧 contact@cyinnove.com