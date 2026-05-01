#!/bin/bash
# Quick run script for CVE-2025-55182 Docker POC
# FOR SECURITY RESEARCH ONLY

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}========================================${NC}"
echo -e "${RED}⚠️  CVE-2025-55182 POC Environment${NC}"
echo -e "${RED}⚠️  FOR SECURITY RESEARCH ONLY${NC}"
echo -e "${RED}========================================${NC}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}[-] Docker is not running!${NC}"
    exit 1
fi

# Parse command line arguments
MODE=${1:-compose}

case $MODE in
    compose)
        echo -e "${BLUE}[*] Starting with Docker Compose...${NC}"
        docker-compose up -d
        echo ""
        echo -e "${GREEN}[+] Services started!${NC}"
        echo ""
        echo "Vulnerable app: http://localhost:3000"
        echo ""
        echo "To run exploit:"
        echo "  docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 -c 'id'"
        echo ""
        echo "To view logs:"
        echo "  docker-compose logs -f"
        echo ""
        echo "To stop:"
        echo "  docker-compose down"
        ;;

    standalone)
        echo -e "${BLUE}[*] Starting standalone vulnerable app...${NC}"
        docker run -d \
            --name react2shell-vulnerable \
            -p 3000:3000 \
            react2shell-vulnerable:latest

        echo ""
        echo -e "${GREEN}[+] Vulnerable app started!${NC}"
        echo ""
        echo "Application: http://localhost:3000"
        echo ""
        echo "To run exploit from host:"
        echo "  python3 exploit.py -t http://localhost:3000 -c 'id'"
        echo ""
        echo "To stop:"
        echo "  docker stop react2shell-vulnerable"
        echo "  docker rm react2shell-vulnerable"
        ;;

    dev)
        echo -e "${BLUE}[*] Starting development environment...${NC}"
        docker-compose --profile dev up -d
        echo ""
        echo -e "${GREEN}[+] Development environment started!${NC}"
        echo ""
        echo "Dev app (hot reload): http://localhost:3001"
        echo "Prod app: http://localhost:3000"
        ;;

    exploit)
        echo -e "${BLUE}[*] Running exploit container...${NC}"
        echo ""

        TARGET=${2:-http://localhost:3000}
        COMMAND=${3:-id}

        echo -e "${YELLOW}Target: $TARGET${NC}"
        echo -e "${YELLOW}Command: $COMMAND${NC}"
        echo ""

        docker run --rm \
            --network host \
            react2shell-exploit:latest \
            python3 exploit.py -t "$TARGET" -c "$COMMAND"
        ;;

    stop)
        echo -e "${BLUE}[*] Stopping all containers...${NC}"
        docker-compose down
        docker stop react2shell-vulnerable 2>/dev/null || true
        docker rm react2shell-vulnerable 2>/dev/null || true
        echo -e "${GREEN}[+] All containers stopped${NC}"
        ;;

    clean)
        echo -e "${BLUE}[*] Cleaning up containers and images...${NC}"
        docker-compose down -v
        docker stop react2shell-vulnerable 2>/dev/null || true
        docker rm react2shell-vulnerable 2>/dev/null || true
        docker rmi react2shell-vulnerable react2shell-dev react2shell-exploit 2>/dev/null || true
        echo -e "${GREEN}[+] Cleanup complete${NC}"
        ;;

    *)
        echo "Usage: $0 [mode]"
        echo ""
        echo "Modes:"
        echo "  compose     - Start with docker-compose (default)"
        echo "  standalone  - Run vulnerable app standalone"
        echo "  dev        - Start dev environment with hot reload"
        echo "  exploit    - Run exploit [target] [command]"
        echo "  stop       - Stop all containers"
        echo "  clean      - Remove all containers and images"
        echo ""
        echo "Examples:"
        echo "  $0 compose"
        echo "  $0 exploit http://localhost:3000 'whoami'"
        echo "  $0 dev"
        echo "  $0 stop"
        exit 1
        ;;
esac
