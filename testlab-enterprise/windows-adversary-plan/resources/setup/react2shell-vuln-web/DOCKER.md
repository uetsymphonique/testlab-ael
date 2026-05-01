# Docker Setup for CVE-2025-55182 POC

## 🐋 Overview

Complete Docker environment for testing CVE-2025-55182 (React2Shell) vulnerability in an isolated, reproducible setup.

## 📦 Available Images

### 1. **Vulnerable Application** (`Dockerfile`)
Production build of vulnerable Next.js app with React 19.0.0

### 2. **Development Environment** (`Dockerfile.dev`)
Development mode with hot reload for code modification

### 3. **Exploit Container** (`Dockerfile.exploit`)
Python-based attacker container with exploit tools

## 🚀 Quick Start

### Option 1: Using Docker Compose (Recommended)

```bash
# Start vulnerable app
docker-compose up -d

# Run exploit
docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 -c "id"

# View logs
docker-compose logs -f

# Stop everything
docker-compose down
```

### Option 2: Using Helper Scripts

```bash
# Build all images
./docker-build.sh

# Run with compose
./docker-run.sh compose

# Run exploit
./docker-run.sh exploit http://localhost:3000 "whoami"

# Stop all containers
./docker-run.sh stop
```

### Option 3: Manual Docker Commands

```bash
# Build vulnerable app
docker build -t react2shell-vulnerable .

# Run vulnerable app
docker run -d -p 3000:3000 --name vulnerable-app react2shell-vulnerable

# Build exploit container
docker build -f Dockerfile.exploit -t react2shell-exploit .

# Run exploit
docker run --network host react2shell-exploit python3 exploit.py -t http://localhost:3000 -c "id"
```

## 📋 Detailed Usage

### Building Images

**Build all images at once:**
```bash
./docker-build.sh
```

**Build individually:**
```bash
# Production vulnerable app
docker build -t react2shell-vulnerable .

# Development environment
docker build -f Dockerfile.dev -t react2shell-dev .

# Exploit container
docker build -f Dockerfile.exploit -t react2shell-exploit .
```

### Running Vulnerable Application

**Docker Compose:**
```bash
docker-compose up -d vulnerable-app
```

**Standalone:**
```bash
docker run -d \
  --name react2shell-vulnerable \
  -p 3000:3000 \
  react2shell-vulnerable:latest
```

**Access:** http://localhost:3000

### Running Development Environment

```bash
# With docker-compose
docker-compose --profile dev up -d

# Standalone with volume mount for hot reload
docker run -d \
  -p 3001:3000 \
  -v $(pwd)/app:/app/app \
  --name react2shell-dev \
  react2shell-dev:latest
```

**Access:** http://localhost:3001

### Running Exploits

**Using Docker Compose:**
```bash
# Basic exploitation
docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 -c "id"

# Custom command
docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 -c "whoami"

# Check vulnerability only
docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 --check-only
```

**Using helper script:**
```bash
./docker-run.sh exploit http://localhost:3000 "id"
./docker-run.sh exploit http://localhost:3000 "cat /etc/passwd"
```

**Standalone exploit container:**
```bash
docker run --rm --network host \
  react2shell-exploit:latest \
  python3 exploit.py -t http://localhost:3000 -c "id"
```

## 🔧 Docker Compose Services

### Service: `vulnerable-app`
- **Port:** 3000
- **Mode:** Production
- **Health Check:** Enabled
- **Auto-restart:** Yes

### Service: `vulnerable-app-dev`
- **Port:** 3001
- **Mode:** Development with hot reload
- **Profile:** `dev`
- **Volumes:** Source code mounted

### Service: `exploit`
- **Network:** Shared with vulnerable-app
- **Profile:** `exploit`
- **Purpose:** Run exploit scripts

## 🌐 Networking

### Docker Compose Network
- **Network Name:** `research-net`
- **Driver:** bridge
- **Subnet:** 172.25.0.0/16

Containers communicate via service names:
- `vulnerable-app:3000` - Production app
- `vulnerable-app-dev:3000` - Dev app

### Host Network Mode
For standalone containers, use `--network host` to access services on localhost.

## 🎯 Common Workflows

### Full POC Demo

```bash
# 1. Build everything
./docker-build.sh

# 2. Start vulnerable app
docker-compose up -d vulnerable-app

# 3. Wait for app to be ready
sleep 5

# 4. Run exploit
docker-compose run exploit python3 exploit.py \
  -t http://vulnerable-app:3000 \
  -c "touch /tmp/pwned && echo 'Exploitation successful'"

# 5. Verify (check logs for command execution)
docker-compose logs vulnerable-app

# 6. Cleanup
docker-compose down
```

### Development Workflow

```bash
# Start dev environment
docker-compose --profile dev up -d

# Make changes to app/page.js or other files
# Changes auto-reload in container

# Test exploit against dev environment
docker-compose run exploit python3 exploit.py -t http://vulnerable-app-dev:3000 -c "id"
```

### Testing Different Payloads

```bash
# Terminal 1: Start app with logs
docker-compose up vulnerable-app

# Terminal 2: Run various exploits
docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 -c "id"
docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 -c "whoami"
docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 -c "env | grep NODE"
docker-compose run exploit python3 exploit.py -t http://vulnerable-app:3000 -c "ls -la /app"
```

## 🔍 Debugging

### View Container Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f vulnerable-app
docker-compose logs -f exploit

# Last 50 lines
docker-compose logs --tail=50 vulnerable-app
```

### Interactive Shell

```bash
# Get shell in vulnerable app
docker-compose exec vulnerable-app sh

# Get shell in exploit container
docker-compose run --rm exploit /bin/bash
```

### Health Check Status

```bash
# Check container health
docker ps
docker inspect vulnerable-app | grep -A 10 Health
```

### Network Inspection

```bash
# List networks
docker network ls

# Inspect research network
docker network inspect hello-world-next-js_research-net

# Check connectivity
docker-compose exec vulnerable-app ping exploit
```

## 🧹 Cleanup

### Stop Services
```bash
# Using docker-compose
docker-compose down

# Using helper script
./docker-run.sh stop

# Manual
docker stop vulnerable-app exploit
docker rm vulnerable-app exploit
```

### Remove Everything
```bash
# Complete cleanup with helper script
./docker-run.sh clean

# Manual cleanup
docker-compose down -v --rmi all
docker rmi react2shell-vulnerable react2shell-dev react2shell-exploit
docker volume prune -f
docker network prune -f
```

## ⚙️ Configuration

### Environment Variables

Set in `docker-compose.yml` or pass to `docker run`:

```bash
# Vulnerable app
NODE_ENV=production
NEXT_TELEMETRY_DISABLED=1
HOSTNAME=0.0.0.0

# Exploit container
TARGET_URL=http://vulnerable-app:3000
PYTHONUNBUFFERED=1
```

### Port Mapping

Default ports:
- `3000` - Production vulnerable app
- `3001` - Development environment (when using dev profile)

Change in `docker-compose.yml`:
```yaml
ports:
  - "8080:3000"  # Map to different host port
```

## 🔐 Security Notes

1. **Isolated Environment:** Containers run in isolated network
2. **Non-root User:** Vulnerable app runs as `node` user (but still exploitable)
3. **No Production Use:** These images contain known vulnerabilities
4. **Research Only:** For authorized security testing only

## 📊 Resource Usage

Typical resource usage:
- **vulnerable-app:** ~100MB RAM, minimal CPU
- **exploit:** ~50MB RAM, minimal CPU

Adjust limits in `docker-compose.yml`:
```yaml
deploy:
  resources:
    limits:
      cpus: '0.5'
      memory: 512M
```

## 🆘 Troubleshooting

### Port Already in Use
```bash
# Find process using port 3000
lsof -i :3000

# Use different port
docker run -p 8080:3000 react2shell-vulnerable
```

### Image Build Fails
```bash
# Clear build cache
docker builder prune -a

# Rebuild without cache
docker build --no-cache -t react2shell-vulnerable .
```

### Container Won't Start
```bash
# Check logs
docker logs vulnerable-app

# Check if port is available
netstat -an | grep 3000

# Remove existing container
docker rm -f vulnerable-app
```

### Exploit Can't Connect
```bash
# Ensure app is running
docker ps | grep vulnerable

# Check health status
docker inspect vulnerable-app | grep Health -A 10

# Test connectivity
curl http://localhost:3000

# Use host network for exploit
docker run --network host react2shell-exploit python3 exploit.py -t http://localhost:3000 -c "id"
```

## 📚 References

- Main README: [README.md](README.md)
- Exploit documentation: [exploit.py](exploit.py)
- Docker Compose reference: [docker-compose.yml](docker-compose.yml)

---

**⚠️ FOR AUTHORIZED SECURITY RESEARCH ONLY**
