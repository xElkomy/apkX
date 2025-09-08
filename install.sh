#!/bin/bash

# apkX Installation Script
# This script helps users install the appropriate apkx binary for their platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 apkX v2.0.0 Installation Script${NC}"
echo "======================================"

# Detect platform and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture names
case $ARCH in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        ;;
    *)
        echo -e "${RED}❌ Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

# Map OS names
case $OS in
    linux)
        OS="linux"
        ;;
    darwin)
        OS="darwin"
        ;;
    *)
        echo -e "${RED}❌ Unsupported operating system: $OS${NC}"
        echo -e "${YELLOW}Supported platforms: Linux, macOS${NC}"
        exit 1
        ;;
esac

BINARY_NAME="apkx-${OS}-${ARCH}"
INSTALL_DIR="/usr/local/bin"
LOCAL_INSTALL_DIR="$HOME/.local/bin"

echo -e "${YELLOW}Detected platform: $OS/$ARCH${NC}"
echo -e "${YELLOW}Binary name: $BINARY_NAME${NC}"

# Check if binary exists in current directory
if [ ! -f "$BINARY_NAME" ]; then
    echo -e "${RED}❌ Binary $BINARY_NAME not found in current directory${NC}"
    echo -e "${YELLOW}Please download the appropriate binary from the GitHub release${NC}"
    echo -e "${BLUE}Download URL: https://github.com/h0tak88r/apkX/releases/tag/v2.0.0${NC}"
    exit 1
fi

# Ask for installation directory
echo -e "${YELLOW}Choose installation directory:${NC}"
echo "1) $INSTALL_DIR (requires sudo)"
echo "2) $LOCAL_INSTALL_DIR (user directory)"
echo "3) Current directory (no installation)"
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        INSTALL_PATH="$INSTALL_DIR"
        SUDO_CMD="sudo"
        ;;
    2)
        INSTALL_PATH="$LOCAL_INSTALL_DIR"
        SUDO_CMD=""
        mkdir -p "$LOCAL_INSTALL_DIR"
        ;;
    3)
        INSTALL_PATH="."
        SUDO_CMD=""
        ;;
    *)
        echo -e "${RED}❌ Invalid choice${NC}"
        exit 1
        ;;
esac

# Install binary
if [ "$INSTALL_PATH" != "." ]; then
    echo -e "${YELLOW}Installing $BINARY_NAME to $INSTALL_PATH...${NC}"
    $SUDO_CMD cp "$BINARY_NAME" "$INSTALL_PATH/apkx"
    $SUDO_CMD chmod +x "$INSTALL_PATH/apkx"
    echo -e "${GREEN}✅ Successfully installed apkx to $INSTALL_PATH${NC}"
    
    # Add to PATH if installing to local directory
    if [ "$INSTALL_PATH" = "$LOCAL_INSTALL_DIR" ]; then
        if ! echo "$PATH" | grep -q "$LOCAL_INSTALL_DIR"; then
            echo -e "${YELLOW}⚠️  Please add $LOCAL_INSTALL_DIR to your PATH${NC}"
            echo -e "${BLUE}Add this line to your ~/.bashrc or ~/.zshrc:${NC}"
            echo -e "${BLUE}export PATH=\"\$PATH:$LOCAL_INSTALL_DIR\"${NC}"
        fi
    fi
else
    echo -e "${YELLOW}Using binary from current directory${NC}"
    chmod +x "$BINARY_NAME"
    echo -e "${GREEN}✅ Binary is ready to use${NC}"
    echo -e "${BLUE}Usage: ./$BINARY_NAME -h${NC}"
fi

# Test installation
if [ "$INSTALL_PATH" != "." ]; then
    echo -e "${YELLOW}Testing installation...${NC}"
    if apkx -h > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Installation successful!${NC}"
        echo -e "${BLUE}Usage: apkx -h${NC}"
    else
        echo -e "${RED}❌ Installation test failed${NC}"
        echo -e "${YELLOW}Please check your PATH or try running: $INSTALL_PATH/apkx -h${NC}"
    fi
fi

echo ""
echo -e "${GREEN}🎉 apkX v2.0.0 is ready to use!${NC}"
echo -e "${BLUE}For more information, visit: https://github.com/h0tak88r/apkX${NC}"
