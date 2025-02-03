# apkX 🔍⏱️

Advanced APK analysis tool with enhanced terminal output and runtime tracking

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GitHub Actions](https://img.shields.io/github/actions/workflow/status/cyinnove/apkX/build.yml)

## Requirements 🛠️
- jadx 1.4.3+
- go 1.21+
- Android SDK (for aapt)
- Java 8 (for jadx)

## Features ✨
- ⏱️ Runtime duration tracking
- 🎨 Colorful terminal output with emoji indicators
- 🔍 Deep APK analysis for:
  - URIs and endpoints
  - Security secrets
  - API keys
  - Sensitive patterns
- 📊 JSON report generation
- 📅 Execution timestamp tracking

## Installation 📦
```bash
git clone git@github.com:cyinnove/apkX.git
cd apkX
go build -o apkx ./cmd/apkx/main.go
```

## Usage 🚀
```bash
./apkx -f <path-to-apk> [flags]

# Example with test APK
./apkx -f sample.apk -json -output results.json
```

## Contributing 🤝
We welcome contributions! Please follow our [contribution guidelines](CONTRIBUTING.md).

---

🔧 Maintained by [Cyinnove](https://github.com/cyinnove) | 📧 contact@cyinnove.com