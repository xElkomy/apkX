# Release Notes - apkX v2.1.0

## 🎉 Enhanced Discord Integration

### ✨ New Features

#### **🤖 Dual Report Discord Integration**
- **Both JSON and HTML reports** are now sent to Discord webhooks
- **Enhanced Discord message** with both file names and descriptions
- **Separate file attachments** for easy access to both formats
- **Professional formatting** with emojis and clear descriptions

#### **🌐 Modern HTML Reports**
- **Dark mode UI** with professional color scheme
- **Sidebar navigation** for easy category browsing
- **Advanced filtering** by risk level and content
- **Search functionality** within each category
- **Interactive context toggles** for detailed information
- **Responsive design** that works on all devices

### 🔧 Improvements

#### **📊 Enhanced Reporting**
- **Better context display** with proper formatting
- **Improved pagination** for large result sets
- **Clean ANSI code stripping** for better readability
- **Professional styling** with modern CSS and animations

#### **🛡️ Security Analysis**
- **Comprehensive vulnerability detection** with 1600+ patterns
- **Task Hijacking detection** for activity launch mode vulnerabilities
- **Janus Vulnerability analysis** for APK signature schemes
- **Insecure Storage detection** for SharedPreferences and SQLite
- **Certificate Pinning checks** for SSL/TLS security
- **Debug Mode detection** for production build validation

### 📦 What's Included

#### **Cross-Platform Binaries**
- **Linux AMD64** - `apkx-linux-amd64.tar.gz`
- **Windows AMD64** - `apkx-windows-amd64.zip`
- **macOS AMD64** - `apkx-darwin-amd64.tar.gz`

#### **Documentation**
- **Updated README** with new Discord integration details
- **Enhanced usage examples** with all new features
- **Comprehensive command reference** for all flags

### 🚀 Usage Examples

#### **Basic Analysis with HTML Report**
```bash
./apkx -html -janus -apk target.apk
```

#### **Full Analysis with Discord Integration**
```bash
./apkx -html -janus -wh "https://discord.com/api/webhooks/your-webhook-url" target.apk
```

#### **Custom Output Directory**
```bash
./apkx -html -janus -o results -w 8 -apk target.apk
```

### 🔄 Migration from v2.0.0

- **No breaking changes** - all existing commands work as before
- **Enhanced Discord integration** - now sends both JSON and HTML reports
- **Improved HTML reports** - better UI and more features
- **Updated documentation** - reflects all new capabilities

### 🐛 Bug Fixes

- **Fixed module import paths** to use correct repository
- **Improved error handling** for Discord webhook failures
- **Enhanced context parsing** for better readability
- **Fixed HTML template rendering** issues

### 📈 Performance

- **Faster HTML generation** with optimized templates
- **Improved memory usage** for large APK files
- **Better caching** for repeated analysis
- **Enhanced concurrent processing** for multiple files

---

**Full Changelog**: https://github.com/h0tak88r/apkX/compare/v2.0.0...v2.1.0

**Download**: https://github.com/h0tak88r/apkX/releases/tag/v2.1.0
