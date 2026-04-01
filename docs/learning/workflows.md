# Workflows

Common use cases and example configurations.

## Getting Started (End-to-End)

Walk through install, run a cell, observe it, and extract output.

### 1. Install and Set Up

```bash
# Install brig.
git clone https://github.com/d0cd/brig.git && cd brig
./install.sh

# Create the VM (one-time, takes a few minutes).
brig init
brig vm create
brig vm start

# Start the Warden proxy inside the VM.
brig vm shell -- warden start --detach

# Verify everything is healthy.
brig health
```

### 2. Run Your First Cell

```bash
# Run a simple cell that fetches an IP address.
brig run --name demo --image alpine -- wget -qO- https://httpbin.org/ip
```

Expected output: your public IP (routed through Warden).

### 3. Run a Detached Cell and Observe

```bash
# Start a long-running cell in the background.
brig run --name worker --image python:3.11-slim -d \
  -- python -c "import time; [print(f'tick {i}', flush=True) or time.sleep(2) for i in range(30)]"

# Watch its logs live.
brig logs worker -f

# Check network activity.
brig network worker

# See resource usage.
brig stats worker

# List all cells.
brig list
```

### 4. Copy Output and Clean Up

```bash
# Copy a file out of the cell workspace.
brig cp worker:/work/output.txt ./output.txt

# Stop and remove the cell.
brig stop worker
brig rm worker
```

### 5. Network Policy

Edit `~/.brig/cells/network-policy.json` to control which domains cells can reach:

```json
{
  "allow": ["api.github.com", "*.amazonaws.com"],
  "deny": ["pastebin.com"]
}
```

Reload without restarting: `brig vm shell -- warden policy reload`

---

## AI Agent Sandbox

Run AI agents that execute arbitrary code safely.

### Configuration

```yaml
# cells/research-agent.yaml
name: research-agent
image: python:3.11-slim

restart: unless-stopped

env:
  TASK_ID: "12345"

secrets:
  - openai-key
  - anthropic-key

files:
  - ./task.json:/work/task.json

command: ["python", "/work/agent.py"]
```

### Network Policy

```yaml
# network-policy.json
default: deny

allow:
  - api.openai.com
  - api.anthropic.com
  - pypi.org
  - "*.pythonhosted.org"
  - github.com
  - "*.githubusercontent.com"

deny:
  - pastebin.com
  - "*.ngrok.io"
```

### Usage

```bash
# Start the agent
brig run -f cells/research-agent.yaml -d

# Watch what it's doing
brig logs research-agent -f

# Watch network activity
brig network research-agent -f

# Check for blocked requests
brig network research-agent --json | jq 'select(.blocked)'

# Get results
brig cp research-agent:/work/output.json ./output.json
```

### Monitoring

```bash
# Resource usage
brig stats research-agent

# Health check
brig health

# All activity
brig logs research-agent --all -f
```

---

## CI/CD Runner

Run untrusted build jobs safely.

### Configuration

```yaml
# cells/ci-runner.yaml
name: ci-runner
image: node:20-slim

# Don't restart - each job is a one-shot
restart: no
timeout: 30m

env:
  CI: "true"
  NODE_ENV: "test"

secrets:
  - npm-token

resources:
  memory: 4g
  cpus: 2

command: ["npm", "run", "build"]
```

### Network Policy

```yaml
default: deny

allow:
  - registry.npmjs.org
  - "*.npmjs.com"
  - github.com
  - "*.githubusercontent.com"
```

### Usage

```bash
# Run the build
brig run -f cells/ci-runner.yaml

# Wait for completion
brig logs ci-runner -f

# Check exit code
brig inspect ci-runner --format json | jq '.State.ExitCode'

# Get artifacts
brig cp ci-runner:/work/dist ./dist

# Cleanup
brig rm ci-runner
```

### Batch Processing

```bash
#!/bin/bash
# Run multiple jobs in parallel

for job in job1 job2 job3; do
  brig run --name "$job" -f cells/ci-runner.yaml -d --rm
done

# Wait for all
for job in job1 job2 job3; do
  brig logs "$job" -f
done
```

---

## Student Code Execution

Run untrusted student submissions safely.

### Configuration

```yaml
# cells/student-runner.yaml
name: student-runner
image: python:3.11-slim

restart: no
timeout: 5m

resources:
  memory: 512m
  cpus: 1
  pids: 128

# No secrets - students don't get API keys

command: ["python", "/work/submission.py"]
```

### Network Policy

```yaml
# Strict - no network access for students
default: deny

# Or allow only specific educational resources
allow:
  - docs.python.org
```

### Usage

```bash
# Copy student submission
cp ./submissions/student123.py ~/.brig/state/student-runner/workspace/submission.py

# Run it
brig run -f cells/student-runner.yaml

# Get output
brig logs student-runner

# Check for network cheating attempts
brig network student-runner --json | jq 'select(.blocked)'

# Cleanup
brig rm student-runner
```

### Grading Multiple Submissions

```bash
#!/bin/bash
# Grade all submissions

for submission in ./submissions/*.py; do
  student=$(basename "$submission" .py)

  # Create workspace
  mkdir -p ~/.brig/state/"$student"/workspace
  cp "$submission" ~/.brig/state/"$student"/workspace/submission.py

  # Run with timeout
  brig run --name "$student" \
    --image python:3.11-slim \
    --timeout 5m \
    -- python /work/submission.py > "results/$student.txt" 2>&1

  echo "$student: exit code $(brig inspect "$student" --format json | jq '.State.ExitCode')"

  brig rm "$student"
done
```

---

## Plugin Sandbox

Run third-party plugins safely.

### Configuration

```yaml
# cells/plugin-sandbox.yaml
name: plugin-sandbox
image: node:20-slim

restart: unless-stopped

env:
  PLUGIN_ID: "my-plugin"

# Only give plugin the API key it needs
secrets:
  - plugin-api-key

resources:
  memory: 256m
  cpus: 0.5
  pids: 64

healthcheck:
  type: http
  command: ["wget", "-q", "--spider", "http://localhost:3000/health"]
  interval: 30s

command: ["node", "/work/plugin.js"]
```

### Network Policy

```yaml
default: deny

# Only allow plugin's declared API
allow:
  - api.plugin-service.com
```

### Usage

```bash
# Start the plugin
brig run -f cells/plugin-sandbox.yaml -d

# Monitor its behavior
brig network plugin-sandbox -f

# Check health
brig health

# Stop misbehaving plugin
brig stop plugin-sandbox
```

---

## Interactive Development

Develop with strict network policies.

### Quick Shell

```bash
# Get an interactive shell
brig run --name dev --image python:3.11-slim -it

# Files in ~/.brig/state/dev/workspace/ appear at /work
```

### Development Workflow

```bash
# Start a dev environment
brig run --name myproject \
  --image python:3.11-slim \
  -d \
  -- tail -f /dev/null

# Edit files on macOS
code ~/.brig/state/myproject/workspace/

# Run commands in the cell
brig exec myproject -- python /work/main.py

# Watch logs
brig logs myproject -f

# Test network behavior
brig network myproject -f
```

### Hot Reload Pattern

```bash
# Terminal 1: Watch for file changes and run tests
brig exec myproject -- sh -c 'while true; do inotifywait -e modify /work/*.py && python -m pytest /work/tests/; done'

# Terminal 2: Watch network
brig network myproject -f

# Terminal 3: Edit files on macOS
code ~/.brig/state/myproject/workspace/
```

---

## Multiple Coordinated Cells

Run multiple cells that communicate through external services.

### Architecture

```
┌─────────────┐     ┌─────────────┐
│  Worker A   │     │  Worker B   │
│    (cell)   │     │    (cell)   │
└──────┬──────┘     └──────┬──────┘
       │                   │
       ▼                   ▼
┌─────────────────────────────────┐
│           Proxy                 │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│     Redis (external service)    │
└─────────────────────────────────┘
```

### Configuration

```yaml
# cells/worker.yaml
name: worker
image: python:3.11-slim

restart: unless-stopped

env:
  REDIS_URL: "redis://your-redis.upstash.io:6379"

secrets:
  - redis-password

command: ["python", "/work/worker.py"]
```

### Network Policy

```yaml
default: deny

allow:
  - "*.upstash.io"  # Managed Redis
```

### Usage

```bash
# Start multiple workers
brig run --name worker-a -f cells/worker.yaml -d
brig run --name worker-b -f cells/worker.yaml -d
brig run --name worker-c -f cells/worker.yaml -d

# Watch all logs
brig logs --all -f

# Watch all network activity
for w in worker-a worker-b worker-c; do
  brig network "$w" -f &
done
```

---

## Long-Running Service

Run a service that survives restarts.

### Configuration

```yaml
# cells/api-server.yaml
name: api-server
image: python:3.11-slim

restart: always

resources:
  memory: 2g
  cpus: 2

healthcheck:
  type: http
  command: ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s

secrets:
  - database-url
  - api-secret

command: ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Usage

```bash
# Start the service
brig run -f cells/api-server.yaml -d

# Check status
brig list
brig health

# View logs
brig logs api-server -f

# The service restarts automatically if it crashes or after VM reboot
```

### Monitoring

```bash
# Resource usage over time
watch -n 5 'brig stats api-server'

# Network summary
brig network api-server --json | jq -s 'group_by(.host) | map({host: .[0].host, count: length})'
```

---

## Using Tor

Route all cell traffic through the Tor network for anonymous egress.

### Architecture

```
Cell → Warden (policy enforcement :8080)
         → Privoxy (HTTP→SOCKS5 bridge :8118)
            → Tor (SOCKS5 proxy :9050)
               → Internet (via Tor network)
```

Cells cannot reach Privoxy or Tor directly — all traffic passes through Warden's policy engine first.

### Quick Start

```bash
# 1. Start the Tor stack (Tor + Privoxy bridge).
warden tor start

# 2. Restart Warden to activate upstream routing.
warden restart

# 3. Verify Tor is active.
warden tor status

# 4. Run a cell — all egress goes through Tor.
brig run --name anon --image python:3.11-slim --tor -- \
  curl -s https://check.torproject.org/api/ip

# 5. Stop Tor when done and restart Warden.
warden tor stop
warden restart
```

### Cell Definition

```yaml
# cells/tor-agent.yaml
name: tor-agent
image: python:3.11-slim
tor: true
command: ["python", "/work/agent.py"]
```

The `tor: true` field adds a pre-flight check that the Tor stack and Warden upstream mode are active before the cell starts.

### Notes

- Tor routing is global — when active, all cells route through Tor.
- The `--tor` flag and `tor:` YAML field only add a pre-flight check; they do not selectively enable Tor per cell.
- Network policy enforcement still applies. Blocked domains remain blocked.
- Expect higher latency through the Tor network.
