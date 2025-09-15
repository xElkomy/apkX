# apkX v3.2.0

## Highlights
- XAPK support: automatic conversion of .xapk to .apk for uploads and downloads
- Resilient MITM flow: if apk-mitm fails, analysis continues on the original APK with a clear note
- HTML report UX: always-visible full context, removed redundant per-finding toggle, fixed menu collapse behavior

## Details
### XAPK → APK
- Detect `.xapk` in upload and download paths
- Extract inner APK from the archive and proceed with optional MITM + analysis

### MITM Patching
- Failure no longer aborts the job
- Job status shows: "MITM patch failed, continuing without patch…"
- Metadata includes `mitm_enabled`, `patched_apk` (when available) and `mitm_failed` flags

### HTML Report
- Removed “Show Full Context” button; context is now always displayed
- Sidebar menu toggle fixed to avoid weird layout when collapsed
- Small CSS/JS cleanups for consistency

## Notes
- Server flag `-mitm` still enables patching globally
- Downloaded patched APK is stored in `web-data/downloads/` when patching succeeds
- Reports saved under `web-data/reports/<run-id>/`

## Upgrade
- No breaking changes
- Rebuild server: `go build -o apkx-web cmd/server/main.go`
