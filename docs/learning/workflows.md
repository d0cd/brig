# Workflows

Common use cases and example configurations.

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
# network-policy.yaml
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
cell run -f cells/research-agent.yaml -d

# Watch what it's doing
cell logs research-agent -f

# Watch network activity
cell network research-agent -f

# Check for blocked requests
cell network research-agent --json | jq 'select(.blocked)'

# Get results
cell cp research-agent:/work/output.json ./output.json
```

### Monitoring

```bash
# Resource usage
cell stats research-agent

# Health check
cell health research-agent

# All activity
cell logs research-agent --all -f
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
cell run -f cells/ci-runner.yaml

# Wait for completion
cell wait ci-runner

# Check exit code
cell inspect ci-runner --format '{{.State.ExitCode}}'

# Get artifacts
cell cp ci-runner:/work/dist ./dist

# Cleanup
cell rm ci-runner
```

### Batch Processing

```bash
#!/bin/bash
# Run multiple jobs in parallel

for job in job1 job2 job3; do
  cell run --name "$job" -f cells/ci-runner.yaml -d --rm
done

# Wait for all
for job in job1 job2 job3; do
  cell wait "$job"
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
cell logs student-runner

# Check for network cheating attempts
cell network student-runner --json | jq 'select(.blocked)'

# Cleanup
cell rm student-runner
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
  cell run --name "$student" \
    --image python:3.11-slim \
    --timeout 5m \
    -- python /work/submission.py > "results/$student.txt" 2>&1

  echo "$student: exit code $(cell inspect "$student" --format '{{.State.ExitCode}}')"

  cell rm "$student"
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
cell run -f cells/plugin-sandbox.yaml -d

# Monitor its behavior
cell network plugin-sandbox -f

# Check health
cell health plugin-sandbox

# Stop misbehaving plugin
cell stop plugin-sandbox
```

---

## Interactive Development

Develop with strict network policies.

### Quick Shell

```bash
# Get an interactive shell
cell run --name dev --image python:3.11-slim -it

# Files in ~/.brig/state/dev/workspace/ appear at /work
```

### Development Workflow

```bash
# Start a dev environment
cell run --name myproject \
  --image python:3.11-slim \
  -d \
  -- tail -f /dev/null

# Edit files on macOS
code ~/.brig/state/myproject/workspace/

# Run commands in the cell
cell exec myproject -- python /work/main.py

# Watch logs
cell logs myproject -f

# Test network behavior
cell network myproject -f
```

### Hot Reload Pattern

```bash
# Terminal 1: Watch for file changes and run tests
cell exec myproject -- sh -c 'while true; do inotifywait -e modify /work/*.py && python -m pytest /work/tests/; done'

# Terminal 2: Watch network
cell network myproject -f

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
cell run --name worker-a -f cells/worker.yaml -d
cell run --name worker-b -f cells/worker.yaml -d
cell run --name worker-c -f cells/worker.yaml -d

# Watch all logs
cell logs --all -f

# Watch all network activity
for w in worker-a worker-b worker-c; do
  cell network "$w" -f &
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
cell run -f cells/api-server.yaml -d

# Check status
cell list
cell health api-server

# View logs
cell logs api-server -f

# The service restarts automatically if it crashes or after VM reboot
```

### Monitoring

```bash
# Resource usage over time
watch -n 5 'cell stats api-server'

# Network summary
cell network api-server --json | jq -s 'group_by(.host) | map({host: .[0].host, count: length})'
```
