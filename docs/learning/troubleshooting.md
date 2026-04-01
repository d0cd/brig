# Troubleshooting

Common issues and how to fix them.

## Cell Can't Reach the Internet

### Quick Diagnosis

```bash
brig diagnose my-cell
```

This shows:
- Proxy status
- Cell network attachment
- Recent blocked requests
- DNS resolution test
- Suggested fixes

### Manual Checks

**1. Is the proxy running?**

```bash
warden status
```

If not running:

```bash
warden start
```

**2. Can the proxy reach the internet?**

```bash
brig vm shell -- podman exec proxy curl -m 5 https://example.com
```

If this fails, check VM network configuration.

**3. Is the cell on the correct network?**

```bash
brig inspect my-cell --format '{{.NetworkSettings.Networks}}'
```

Should show `brig-my-cell` network.

**4. Can the cell reach the proxy?**

```bash
brig exec my-cell -- curl -v http://proxy:8080/
```

If DNS fails, the proxy isn't joined to the cell's network:

```bash
brig vm shell -- podman network connect brig-my-cell warden
```

**5. Is the domain blocked?**

```bash
brig network my-cell --json | jq 'select(.blocked)' | tail -5
```

If your domain is being blocked, add it to `~/.brig/cells/network-policy.json` and reload:

```bash
warden reload
```

---

## Cell Seems Stuck

### Check Logs

```bash
# stdout
brig logs my-cell

# stderr (often has errors)
brig logs my-cell --stderr

# Both
brig logs my-cell --all
```

### Check What's Running

```bash
brig exec my-cell -- ps aux
```

### Check Resource Usage

```bash
brig stats my-cell
```

If memory is maxed out, the cell might be OOM-killed. Increase limits:

```yaml
resources:
  memory: 4g
```

### Check for Blocking Network Calls

A cell waiting on a blocked network request will hang until timeout:

```bash
brig network my-cell -f
```

If you see requests being blocked, either:
- Add the domain to the allowlist
- Fix the cell to not make that request

---

## gVisor Compatibility Issues

Some programs don't work with gVisor (rare).

### Symptoms

- Program crashes with syscall errors
- "function not implemented" errors
- Unexpected behavior compared to normal containers

### Diagnosis

```bash
# Check gVisor logs
brig vm shell -- journalctl -u podman -f | grep runsc

# Check if gVisor is actually active
brig inspect my-cell --runtime
# Should output: runsc
```

### Workarounds

**1. Check if the issue is documented**

See [gVisor compatibility docs](https://gvisor.dev/docs/user_guide/compatibility/).

**2. Test without gVisor (less secure)**

```bash
brig run --name test --runtime=runc --unsafe -- your-command
```

If this works, you have a gVisor compatibility issue.

**3. Use a different approach**

Often there's an alternative that works with gVisor:
- Different library version
- Different implementation
- Workaround in your code

---

## Network Isolation Test Fails

If Test 1 (direct internet access) succeeds when it shouldn't:

### Check Network is Internal

```bash
brig vm shell -- podman network inspect brig-my-cell | grep -i internal
# Should show: "internal": true
```

### Check No Gateway is Set

```bash
brig vm shell -- podman network inspect brig-my-cell | grep -i gateway
# Should show: "gateway": ""
```

### Recreate the Network

```bash
brig rm my-cell
brig run -f cells/my-cell.yaml
```

### Check Cell Isn't Attached to Extra Networks

```bash
brig vm shell -- podman inspect my-cell --format '{{len .NetworkSettings.Networks}}'
# Should be: 1
```

---

## Proxy Won't Start

### Check Systemd Status

```bash
brig vm shell -- systemctl status warden.service
```

### Check Logs

```bash
brig vm shell -- journalctl -u warden.service -n 50
```

### Common Issues

**1. Addon files missing**

```bash
brig vm shell -- ls -la /cells/addons/
# Should have: enforce.py, logger.py
```

If missing, check your `~/.brig/cells/addons/` directory.

**2. Port already in use**

```bash
brig vm shell -- ss -tlnp | grep 8080
```

Kill any existing proxy container:

```bash
brig vm shell -- podman rm -f proxy
warden start
```

**3. Image pull failed**

```bash
brig vm shell -- podman pull mitmproxy/mitmproxy:10.2.4
```

---

## Cell Can't Read Secrets

### Check Secret File Exists

```bash
ls -la ~/.brig/secrets/
```

### Check Secret is Declared

Your cell definition must declare the secret:

```yaml
secrets:
  - openai-key
```

### Validate Before Running

```bash
brig secrets validate my-cell
```

### Check Secret is Mounted

```bash
brig exec my-cell -- ls -la /run/secrets/
brig exec my-cell -- cat /run/secrets/openai-key
```

---

## High Memory Usage

### Check Current Usage

```bash
brig stats
```

### Check for Memory Leaks

```bash
# Watch usage over time
watch -n 5 'brig stats my-cell'
```

### Increase Limits

```yaml
resources:
  memory: 4g
```

### Check VM Resources

```bash
brig vm shell -- free -h
```

If the VM itself is low on memory, edit `~/.brig/lima.yaml`:

```yaml
memory: 16GiB
```

Then recreate the VM:

```bash
brig vm recreate
```

---

## Logs Are Missing

### Check Log Rotation

Logs rotate daily and keep 7 days:

```bash
brig vm shell -- ls -la /state/my-cell/
```

### Check Log Directory Exists

```bash
brig vm shell -- ls -la /var/log/brig/network/
```

### Force Log Rotation

```bash
brig vm shell -- sudo logrotate -f /etc/logrotate.d/cells
```

---

## Cell Won't Start After VM Restart

### Check Proxy Started

The proxy must start before cells:

```bash
warden status
```

If not running:

```bash
warden start
```

### Start Cells

```bash
brig start --all
# Or specific cell
brig start my-cell
```

### Check Restart Policy

For automatic restarts, set restart policy:

```yaml
restart: unless-stopped
```

---

## Verification Fails

### Run Full Verification

```bash
brig verify
```

### Common Failures

**1. Unexpected container on network**

```bash
# Find the container
brig vm shell -- podman network inspect brig-my-cell

# Disconnect it
brig vm shell -- podman network disconnect brig-my-cell unexpected-container
```

**2. Cell on multiple networks**

```bash
brig vm shell -- podman inspect my-cell --format '{{.NetworkSettings.Networks}}'
```

Remove extra network connections or recreate the cell.

**3. Wrong runtime**

```bash
brig inspect my-cell --runtime
# Should be: runsc
```

If wrong, stop and recreate with correct runtime.

---

## Diagnosis Commands Reference

| Issue | Command |
|-------|---------|
| General diagnosis | `brig diagnose my-cell` |
| Proxy status | `warden status` |
| Cell status | `brig list` |
| Cell logs | `brig logs my-cell --all` |
| Network activity | `brig network my-cell -f` |
| Blocked requests | `brig network my-cell --json \| jq 'select(.blocked)'` |
| Resource usage | `brig stats my-cell` |
| Runtime check | `brig inspect my-cell --runtime` |
| Network check | `brig verify` |
| VM shell | `brig vm shell` |
| Proxy logs | `warden logs -f` |
