# Changelog

## [v2.0.0] - 2025-09-07
## [v3.2.0] - 2025-09-15
### Added
- XAPK auto-conversion for uploads and downloads
- Metadata flag `mitm_failed` when patching fails

### Changed
- MITM patching no longer aborts jobs on failure; analysis proceeds
- HTML report: always show full context; removed redundant toggle
- Sidebar menu toggle behavior fixed on large screens

### Notes
- See RELEASE_NOTES_v3.2.0.md for details

### Added
- 🌐 **HTML Report Generation**: Beautiful interactive web-based reports
- 🚨 **Janus Vulnerability Detection**: APK signature scheme analysis (V1/V2/V3)
- 🔒 **Comprehensive Security Checks**:
  - Insecure storage analysis (SharedPreferences, SQLite)
  - Certificate pinning detection
  - Debug mode validation
- 📄 **Interactive Features**:
  - Pagination for large result sets
  - Context toggling in HTML reports
  - Clean, readable formatting
- 🎨 **Enhanced UI**:
  - ANSI code stripping for clean HTML output
  - Responsive design for mobile and desktop
  - Improved vulnerability categorization

### Changed
- 🔧 **Fixed Task Hijacking Count**: Now correctly shows single finding instead of multiple
- 🗑️ **Removed Duplicate Scanning**: Eliminated hardcoded credentials from InsecureStorage analyzer
- 📊 **Improved Reporting**: Better categorization and context display
- 🎯 **Enhanced Accuracy**: More precise vulnerability detection and counting

### Technical Improvements
- Added `SetAPKPath` method to analyzer interface
- Improved context parsing and formatting
- Enhanced HTML template with JavaScript functionality
- Better error handling and validation

## [v1.4.0] - 2024-03-24
### Added
- New task hijacking vulnerability scanner
- Ability to scan AndroidManifest.xml for singleTask launch mode
- New `-task-hijacking` flag for focused vulnerability scanning
- Enhanced terminal output with better formatting and colors
- Detailed vulnerability reports with severity levels

### Changed
- Improved output formatting with box-drawing characters
- Better error handling for manifest parsing
- Enhanced worker output messages

## [v1.3.0] - Previous version
... 