#!/bin/bash

# Cross-platform build script for apkX v2.0.0
# This script builds binaries for multiple platforms and architectures

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Building apkX v2.0.0 cross-platform binaries${NC}"
echo "=================================================="

# Create release directory
RELEASE_DIR="release"
mkdir -p $RELEASE_DIR

# Build configurations
# Format: GOOS/GOARCH/SUFFIX
PLATFORMS=(
    "linux/amd64/apkx-linux-amd64"
    "linux/arm64/apkx-linux-arm64"
    "darwin/amd64/apkx-darwin-amd64"
    "darwin/arm64/apkx-darwin-arm64"
    "windows/amd64/apkx-windows-amd64.exe"
    "windows/arm64/apkx-windows-arm64.exe"
)

# Build function
build_platform() {
    local GOOS=$1
    local GOARCH=$2
    local OUTPUT=$3
    
    echo -e "${YELLOW}Building for $GOOS/$GOARCH...${NC}"
    
    GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="-s -w -X main.version=v2.0.0" \
        -o "$RELEASE_DIR/$OUTPUT" \
        cmd/apkx/main.go
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Successfully built $OUTPUT${NC}"
        
        # Get file size
        if command -v du >/dev/null 2>&1; then
            SIZE=$(du -h "$RELEASE_DIR/$OUTPUT" | cut -f1)
            echo -e "   Size: $SIZE"
        fi
    else
        echo -e "${RED}❌ Failed to build $OUTPUT${NC}"
        exit 1
    fi
    echo ""
}

# Build all platforms
for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r GOOS GOARCH OUTPUT <<< "$platform"
    build_platform $GOOS $GOARCH $OUTPUT
done

# Create checksums
echo -e "${BLUE}📋 Creating checksums...${NC}"
cd $RELEASE_DIR
if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * > checksums.txt
    echo -e "${GREEN}✅ Created checksums.txt${NC}"
elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum * > checksums.txt
    echo -e "${GREEN}✅ Created checksums.txt${NC}"
else
    echo -e "${YELLOW}⚠️  Could not create checksums (shasum/sha256sum not found)${NC}"
fi
cd ..

# Create release info
echo -e "${BLUE}📄 Creating release info...${NC}"
cat > $RELEASE_DIR/RELEASE_INFO.txt << EOF
apkX v2.0.0 Cross-Platform Release
==================================

Build Date: $(date)
Go Version: $(go version)
Build Host: $(uname -s) $(uname -m)

Available Binaries:
- apkx-linux-amd64 (Linux x86_64)
- apkx-linux-arm64 (Linux ARM64)
- apkx-darwin-amd64 (macOS x86_64)
- apkx-darwin-arm64 (macOS ARM64/Apple Silicon)
- apkx-windows-amd64.exe (Windows x86_64)
- apkx-windows-arm64.exe (Windows ARM64)

Usage:
1. Download the binary for your platform
2. Make it executable (Unix systems): chmod +x apkx-*
3. Run: ./apkx-* -h for help

Features:
- HTML report generation (-html)
- Janus vulnerability detection (-janus)
- Task hijacking analysis (-task-hijacking)
- Comprehensive security analysis
- Cross-platform compatibility

For more information, visit: https://github.com/h0tak88r/apkX
EOF

echo -e "${GREEN}✅ Created RELEASE_INFO.txt${NC}"

# List all files
echo -e "${BLUE}📁 Release files:${NC}"
ls -la $RELEASE_DIR/

echo ""
echo -e "${GREEN}🎉 Cross-platform build completed successfully!${NC}"
echo -e "${BLUE}📦 Release files are in the '$RELEASE_DIR' directory${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Test the binaries on different platforms"
echo "2. Create a GitHub release"
echo "3. Upload the files from the '$RELEASE_DIR' directory"
echo "4. Include the RELEASE_INFO.txt content in the release notes"
