# Concepts

User-facing explanations of *why* Brig is built the way it is — what
each layer protects you from, what it doesn't, and what you should
expect when you use it. For the component-level breakdown (how the
pieces wire together, network topology, deployment), see
[`design/architecture.md`](../design/architecture.md).

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

gVisor is **mandatory** for cells — no flag, profile, or yaml field disables it
(invariant 5: gVisor must be active, no silent downgrade). The `dev` profile only
raises resource limits (memory / cpus / pids); it does not change the runtime. If
a workload genuinely can't run under gVisor's syscall surface, it can't run as a
brig cell — that's the security boundary, not a setting to turn off.

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

Egress allow/deny is **per-cell** and **default-deny** — a cell with no policy
reaches nothing. Rules live in the cell's `policy:` block (or a trust profile)
and can be edited live with `brig policy set <cell>`:

```yaml
# in a cell yaml
policy:
  allow:
    - pypi.org
    - "*.pythonhosted.org"
    - github.com
    - api.openai.com
  deny:
    - pastebin.com
    - "*.ngrok.io"
```

Requests to non-allowed domains return 403. The process-wide
`~/.brig/cells/network-policy.json` holds only operational settings (rate
limits, log filtering, policy tracing) — no allow/deny rules.

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

2. **Create secret files** on macOS — the file name is exactly the
   secret name (no extension):
   ```
   ~/.brig/secrets/openai-key       # Contains: sk-...
   ~/.brig/secrets/anthropic-key    # Contains: sk-ant-...
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

Network logs are stored separately in `/var/log/brig/network/` inside the VM. Cells cannot access or modify them.

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
   brig cell read my-cell /work/output.txt
   brig cell files my-cell
   ```

2. Export safely — sanitization is automatic on every `cell cp` out of a cell;
   there is no flag to enable or disable it:
   ```bash
   brig cell cp my-cell:/work/report.html ./report.html
   ```

3. Never run files directly from the state directory

### What export sanitization does

Every file copied out of a cell gets a macOS **quarantine xattr** (Gatekeeper
treats it as downloaded from an untrusted source). Files whose extension is in
the unsafe-executable set additionally have their **execute bits stripped**.
Nothing is dropped — you always get the file; brig just makes cell-written files
non-executable and marks them untrusted.

| Type | Examples | On export |
|------|----------|-----------|
| Unsafe executables | `.app`, `.command`, `.scpt`, `.dmg`, `.pkg`, `.webloc`, `.jar`, `.exe`, `.bat`, `.cmd`, `.msi`, `.vbs`, `.ps1` | quarantined + execute bits removed |
| Everything else | `.py`, `.sh`, `.pdf`, `.docx`, `.json`, `.csv`, `.png` | quarantined (copied as-is) |
