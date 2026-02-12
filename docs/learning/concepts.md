# Concepts

Deep dives into how Brig works.

## Lima VM as Security Boundary

The Lima VM is Brig's **only hard security boundary**. It provides hardware virtualization using Apple's Virtualization.framework (VZ).

### Why a VM?

Containers share the host kernel. A kernel exploit in a container could compromise the host. The Lima VM creates a hardware boundary:

```
macOS Host (Protected)
    └── Lima VM (Boundary)
            └── Podman Containers
                    └── Your Workloads
```

### What the VM Protects

| Threat | Protection |
|--------|------------|
| Filesystem access | VM has limited mounts |
| Network access | VM controls all egress |
| Process visibility | macOS can't see container processes |
| Kernel exploits | Exploit stays in VM kernel |

### What Survives VM Restart

| Data | Location | Survives? |
|------|----------|-----------|
| Workspaces | `~/.brig/state/` (macOS) | Yes |
| Secrets | `~/.brig/secrets/` (macOS) | Yes |
| Cell configs | `~/.brig/cells/` (macOS) | Yes |
| Running containers | VM | No |
| Cell networks | VM | No |

---

## gVisor: Defense in Depth (Not a Boundary)

gVisor is a user-space kernel that intercepts syscalls from containers. It runs inside the Lima VM.

### What gVisor Does

Instead of containers making syscalls directly to the Linux kernel:

```
Without gVisor:
Container → Linux Kernel (attack surface)

With gVisor:
Container → gVisor (limited syscalls) → Linux Kernel
```

### Important Clarification

**gVisor is not a security boundary.** It's defense-in-depth:

- If gVisor has a vulnerability, the Lima VM still protects macOS
- If both gVisor and the Lima kernel are compromised, macOS is protected by the VM
- gVisor reduces attack surface but doesn't eliminate it

### When gVisor Helps

- Reduces the syscall surface available to workloads
- Provides additional isolation between cells
- Mitigates some kernel exploit classes

### gVisor Limitations

Some programs don't work with gVisor:
- Programs that use unsupported syscalls
- Some network tools
- Programs with specific kernel dependencies

If you must run without gVisor (not recommended):

```bash
brig run --name test --runtime=runc --unsafe -- your-command
```

---

## Per-Cell Network Isolation

Each cell gets its own isolated network. This is the key to Brig's security model.

### How It Works

```
┌──────────────────┐  ┌──────────────────┐
│    cell-a        │  │    cell-b        │
│   (--internal)   │  │   (--internal)   │
│                  │  │                  │
│  ┌────────────┐  │  │  ┌────────────┐  │
│  │   Cell A   │  │  │  │   Cell B   │  │
│  └─────┬──────┘  │  │  └─────┬──────┘  │
│        │         │  │        │         │
│  ┌─────┴──────┐  │  │  ┌─────┴──────┐  │
│  │   Proxy    │  │  │  │   Proxy    │  │
│  └────────────┘  │  │  └────────────┘  │
└──────────────────┘  └──────────────────┘
```

Key properties:

1. **Internal networks**: Created with `--internal` flag, no route to internet
2. **No east-west traffic**: Cells on different networks can't talk to each other
3. **Proxy is the only bridge**: Proxy joins each cell's network

### Why Per-Cell Networks?

| Approach | Problem |
|----------|---------|
| Shared network + iptables | Rule ordering bugs, hard to audit |
| Shared network + namespaces | Complex, easy to misconfigure |
| **Per-cell networks** | Isolation by topology, self-evidently correct |

### Inter-Cell Communication

If cells need to communicate, they go through external services:

```
Cell A → Proxy → Internet → Your API → Internet → Proxy → Cell B
```

All traffic is logged and observable.

---

## Proxy Enforcement Model

The proxy is a mandatory choke point for all network egress.

### Why Cells Can't Bypass the Proxy

1. **Internal networks**: Cell networks have no route to internet
2. **No IP forwarding**: Proxy has `ip_forward=0`
3. **VM-level firewall**: Fail-closed egress rules

Even if a cell ignores `HTTP_PROXY` environment variables, it still can't reach the internet directly.

### What the Proxy Does

| Function | Description |
|----------|-------------|
| Route traffic | All HTTP/HTTPS goes through it |
| Enforce policy | Block requests to non-allowed domains |
| Log requests | Record URL, status, timing per cell |
| Identify cells | Track which cell made each request |

### Policy Enforcement

```yaml
# network-policy.yaml
default: deny

allow:
  - pypi.org
  - "*.pythonhosted.org"
  - github.com
  - api.openai.com

deny:
  - pastebin.com
  - "*.ngrok.io"
```

Requests to non-allowed domains return 403.

### Hot Reload

Policy can be reloaded without restarting the proxy:

```bash
warden reload
```

During reload:
- In-flight requests complete with old policy
- New requests use new policy
- Default-deny is always active

---

## Secrets Model (Files, Not Env Vars)

Brig mounts secrets as files, not environment variables.

### Why Files?

Environment variables leak easily:
- `ps aux` can show env vars
- Crash dumps include env vars
- Debug logs capture env vars
- `podman inspect` shows env vars

Files are more secure:
- Must be explicitly read
- Not in process listings
- Not in crash dumps by default

### How It Works

1. **Declare secrets** in cell definition:
   ```yaml
   secrets:
     - openai-key
     - anthropic-key
   ```

2. **Create secret files** on macOS:
   ```
   ~/.brig/secrets/openai-key.txt    # Contains: sk-...
   ~/.brig/secrets/anthropic-key.txt # Contains: sk-ant-...
   ```

3. **Cell sees**:
   - File at `/run/secrets/openai-key`
   - Env var `OPENAI_KEY_FILE=/run/secrets/openai-key`

4. **Your code reads** the file:
   ```python
   import os
   with open(os.environ["OPENAI_KEY_FILE"]) as f:
       api_key = f.read().strip()
   ```

### Minimal Privilege

Cells only get the secrets they declare:

```yaml
# research-agent.yaml - gets OpenAI key
secrets:
  - openai-key

# github-bot.yaml - gets GitHub token
secrets:
  - github-token
```

Check who gets what:

```bash
grep -r "secrets:" ~/.brig/cells/
```

---

## State Isolation

Each cell's state is completely separate.

### Directory Structure

```
~/.brig/state/
├── cell-a/
│   ├── workspace/      # Only cell-a sees this at /work
│   ├── stdout.log
│   └── stderr.log
├── cell-b/
│   ├── workspace/      # Only cell-b sees this at /work
│   └── ...
└── cell-c/
    └── ...
```

### What Cells Can Access

| Path in Cell | Source | Access |
|--------------|--------|--------|
| `/work` | Cell's own workspace | Read/Write |
| `/run/secrets/*` | Declared secrets | Read-only |
| Other cell workspaces | N/A | Not visible |

### Network Logs

Network logs are stored separately in `/var/log/cells/network/` inside the VM. Cells cannot access or modify them.

---

## macOS State Protection

The `~/.brig/state/` directory contains untrusted output from cells.

### Protection Mechanisms

1. **Quarantine attribute**: Prevents Finder from executing files
   ```bash
   xattr -w com.apple.quarantine "0181;..." ~/.brig/state
   ```

2. **Restricted permissions**: Only your user can access
   ```bash
   chmod 700 ~/.brig/state
   ```

### Safe Workflow

1. Review files inside the VM first:
   ```bash
   brig cat my-cell /work/output.txt
   brig files my-cell
   ```

2. Export with sanitization:
   ```bash
   brig cp --sanitize my-cell:/work/report.html ./report.html
   ```

3. Never run from state directory directly

### What Gets Blocked by `--sanitize`

| Type | Examples | Action |
|------|----------|--------|
| Executables | `.app`, `.command`, `.exe` | Blocked |
| Scripts | `.sh`, `.py`, `.js` | Blocked unless `--allow-scripts` |
| Office docs | `.docx`, `.pdf` | Blocked unless `--allow-office` |
| Data files | `.json`, `.csv`, `.txt` | Allowed |
| Images | `.png`, `.jpg` | Allowed |
