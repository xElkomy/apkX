# apkX v3.0.0 Release Notes

## 🚀 Major Release - Advanced Web Portal & MITM Integration

### 🆕 New Features

#### 🔧 MITM Patching Integration
- **apk-mitm Integration**: Apply HTTPS inspection patches using the `apk-mitm` tool
- **Smart Analysis**: Analysis is performed on the original APK while keeping the patched version for download
- **Automatic Patching**: Seamless integration with the web interface
- **Flag Support**: `-mitm` flag to enable MITM patching globally

#### ⬇️ APK Download System
- **Multiple Sources**: Download APKs from APKPure, Google Play Store, F-Droid, and Huawei AppGallery
- **Package Name Search**: Enter package names directly (e.g., `com.instagram.android`)
- **Version Control**: Specify exact versions or download the latest
- **Google Play Support**: Full OAuth token and AAS token support for Google Play downloads
- **XAPK Support**: Handle both APK and XAPK files seamlessly

#### ⚡ Asynchronous Processing
- **Non-blocking Operations**: Upload and download operations don't block the UI
- **Real-time Status**: Live job status updates with progress tracking
- **Job Management**: View active jobs, completed jobs, and failed jobs
- **Background Processing**: All analysis runs in the background

#### 🎯 Smart Download System
- **Intelligent APK Selection**: 
  - If MITM was enabled → Download the patched APK (ready for HTTPS inspection)
  - If MITM was not enabled → Download the original APK
- **Seamless User Experience**: Users get the right APK for their needs automatically

#### 📊 Enhanced Reporting
- **Package Information**: Extract and display package name and version in HTML reports
- **Report Management**: Delete reports directly from the web interface
- **Better Context**: Improved vulnerability context display in HTML reports

#### 🎨 UI/UX Improvements
- **Tabbed Interface**: Separate tabs for file upload and APK download
- **Job Status Tracking**: Real-time updates for ongoing analysis jobs
- **Enhanced Forms**: Better form validation and user feedback
- **Responsive Design**: Improved mobile and desktop experience

### 🔧 Technical Improvements

#### Backend Architecture
- **Job Management System**: Complete job lifecycle management with status tracking
- **Async Processing**: Goroutine-based background processing
- **Smart File Handling**: Intelligent APK file location and serving
- **Metadata Storage**: JSON-based metadata storage for better file management

#### Security Analysis
- **Original APK Analysis**: Security analysis now uses the original APK for accurate results
- **Patched APK Storage**: Patched APKs are stored separately for download purposes
- **Better Context**: Improved vulnerability context extraction and display

#### Web Interface
- **Modern UI**: Enhanced user interface with better visual feedback
- **Real-time Updates**: Live job status updates without page refresh
- **Better Error Handling**: Improved error messages and user guidance
- **Form Validation**: Better client-side and server-side validation

### 🛠️ Configuration

#### New Server Flags
```bash
# Enable MITM patching globally
./apkx-web -mitm

# Download APK with MITM patching
curl -X POST -F "package=com.instagram.android" -F "mitm_patch=on" http://localhost:9090/download
```

#### Environment Variables
```bash
# Set default port
export PORT=9090

# Set default Discord webhook
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/XXX/YYY"
```

### 📋 Migration Guide

#### From v2.1.0 to v3.0.0
- **No Breaking Changes**: All existing functionality remains the same
- **New Features**: MITM patching and APK download are optional additions
- **Enhanced UI**: The interface has been improved but remains backward compatible
- **Better Performance**: Asynchronous processing improves responsiveness

#### File Structure Changes
- **New Directory**: `internal/downloader/` for APK download functionality
- **Enhanced Metadata**: `apk.name` files now store JSON metadata instead of plain text
- **Backward Compatibility**: Old metadata format is still supported

### 🐛 Bug Fixes
- **Context Display**: Fixed vulnerability context not showing correctly in HTML reports
- **File Type Detection**: Improved APK/XAPK file type detection and handling
- **Error Handling**: Better error messages and recovery mechanisms
- **Memory Management**: Improved memory usage during large file processing

### 🔄 Dependencies
- **apk-mitm**: Required for MITM patching functionality (install via npm)
- **apkeep**: Required for APK download functionality (install via pip)
- **JADX**: Still required for APK decompilation

### 📈 Performance Improvements
- **Async Processing**: Non-blocking operations improve UI responsiveness
- **Better Caching**: Improved file caching and management
- **Memory Optimization**: Better memory usage during large file processing
- **Concurrent Jobs**: Multiple analysis jobs can run simultaneously

### 🎯 Use Cases

#### Security Researchers
- **HTTPS Inspection**: Apply MITM patches for network traffic analysis
- **APK Analysis**: Download and analyze APKs from multiple sources
- **Automated Workflows**: Use Discord webhooks for automated analysis pipelines

#### Penetration Testers
- **Dynamic Analysis**: Download patched APKs for dynamic testing
- **Source Diversity**: Access APKs from different app stores
- **Batch Processing**: Handle multiple APKs with job management

#### Developers
- **Security Auditing**: Analyze your own APKs for security vulnerabilities
- **Competitor Analysis**: Download and analyze competitor APKs
- **Automated Testing**: Integrate with CI/CD pipelines using Discord webhooks

### 🚀 Getting Started

1. **Install Dependencies**:
   ```bash
   npm install -g apk-mitm
   pip install apkeep
   ```

2. **Start the Server**:
   ```bash
   ./apkx-web -addr :9090 -mitm
   ```

3. **Access the Web Interface**:
   - Open `http://localhost:9090`
   - Upload APK files or download by package name
   - Enable MITM patching for HTTPS inspection
   - View real-time job status and download reports

### 📞 Support
- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Check the README.md for detailed usage instructions
- **Discord**: Join our Discord server for community support

---

**apkX v3.0.0** - Advanced APK analysis with MITM integration and smart download system! 🎉
