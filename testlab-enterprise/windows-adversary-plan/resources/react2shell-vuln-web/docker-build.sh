#!/bin/bash
# Build script for CVE-2025-55182 Docker images
# FOR SECURITY RESEARCH ONLY

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}CVE-2025-55182 Docker Build Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to build an image
build_image() {
    local dockerfile=$1
    local tag=$2
    local description=$3

    echo -e "${BLUE}[*] Building $description...${NC}"
    if docker build -f "$dockerfile" -t "$tag" .; then
        echo -e "${GREEN}[+] Successfully built $tag${NC}"
        return 0
    else
        echo -e "${RED}[-] Failed to build $tag${NC}"
        return 1
    fi
    echo ""
}

# Build production vulnerable app
build_image "Dockerfile" "react2shell-vulnerable:latest" "Production vulnerable app"

# Build development version
build_image "Dockerfile.dev" "react2shell-dev:latest" "Development environment"

# Build exploit container
build_image "Dockerfile.exploit" "react2shell-exploit:latest" "Exploit container"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Available images:"
docker images | grep react2shell

echo ""
echo "Quick start commands:"
echo "  1. Run vulnerable app:  docker run -p 3000:3000 react2shell-vulnerable"
echo "  2. Run with compose:    docker-compose up -d"
echo "  3. Run exploit:         docker run --network host react2shell-exploit python3 exploit.py -t http://localhost:3000 -c 'id'"
echo ""
