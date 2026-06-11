# Writing a Cell

This walks through building up a cell YAML from the smallest thing
that runs to a fully-equipped agent. Each step adds one concept.
For the full schema see
[cell-definition.md](../design/cell-definition.md); for background see
[concepts.md](concepts.md).

## The minimum

A cell needs a name and an image. Save as `mycell.yaml`:

```yaml
name: hello
image: alpine
```

Run it:

```bash
brig run --file mycell.yaml
```

The cell starts with the image's default entrypoint, no command,
no env, no secrets, the per-cell isolated network (default), and
all egress denied (cell has no per-cell policy yet).

## Adding a command

```yaml
name: hello
image: alpine
command: ["sh", "-c", "echo 'hello from a cell'; sleep 5"]
```

`command` is a string or a list. A list is preferred — no surprise
shell parsing.

## Environment variables

```yaml
name: hello
image: alpine
command: ["sh", "-c", "echo \"$GREETING\""]
env:
  - GREETING=hello-from-yaml
```

`env` accepts a list of `KEY=VALUE` strings or a dict. Sensitive
values do NOT go here — see secrets below.

## Secrets

Brig mounts secrets as files at `/run/secrets/<name>`, not env vars.
Add the secret on the host first, then declare it in the cell yaml.

```bash
brig secrets add openrouter-key      # interactive prompt
```

```yaml
name: agent
image: python:3.12
command: ["python", "-c", "print(open('/run/secrets/openrouter-key').read())"]
secrets:
  - openrouter-key
```

`secrets:` items must match `^[a-z0-9._-]+$` and must already exist
under `~/.brig/secrets/`.

## Reaching a host service over HTTP

Declare an `host_services` entry to let the cell reach a port on the
macOS host through warden. The cell resolves `<name>.host.brig`; warden
rewrites that to the host IP + the declared port.

```yaml
name: agent
image: python:3.12
command: ["curl", "http://model.host.brig/health"]
host_services:
  - name: model
    port: 11434           # e.g. an llama.cpp / ollama server on the host
    protocol: http        # default; set to "tcp" for raw L4 forwarding
```

The yaml declaration IS the grant — there is no separate global
registry. The `untrusted` profile rejects `host_services` at parse
time.

## Accepting inbound HTTP from the host

Declare an `ingress` entry to make a cell-internal port reachable
from outside the VM through warden's reverse proxy on
`https://warden:8443/<cell>/<prefix>/...`.

```yaml
name: agent
image: python:3.12
command: ["python", "-m", "http.server", "8000"]
ingress:
  - name: api
    port: 8000
    path_prefix: /api
    auth: token
```

`auth: token` requires a secret named `<cell>-ingress-token` (or
`ingress-token` as a fallback). Add it with `brig secrets add agent-ingress-token`.
Use `auth: none` instead for a service that authenticates itself (or a browser
WebSocket client that can't send an `Authorization` header) — brig then proxies
transparently and the app is the gate. `auth: none` isn't allowed on the
`untrusted` profile.

## Egress policy

By default a cell with no `policy:` block has no allowed
destinations. List the domains the cell needs:

```yaml
name: agent
image: python:3.12
command: ["python", "agent.py"]
policy:
  allow:
    - api.openai.com
    - "*.githubusercontent.com"
  deny:
    - "*.ngrok.io"
```

Wildcards match on dot-boundary (`*.example.com` matches
`api.example.com` but not `evilexample.com`).

For hosts whose TLS stack refuses mitmproxy (HPKP, ECH,
Cloudflare-fronted endpoints), opt them out of MITM:

```yaml
policy:
  allow:
    - chatgpt.com           # passthrough hosts MUST also appear in allow
  tls_passthrough:
    - chatgpt.com
```

See invariant 11 in [INVARIANTS.md](../INVARIANTS.md) for the
security trade-off this involves.

## Putting it together

A worked example combining the pieces above:

```yaml
name: my-agent
image: localhost/my-agent:latest
command: ["python", "-m", "my_agent"]
memory: 2g
cpus: "2"
env:
  - MODEL_BASE_URL=http://model.host.brig
secrets:
  - openrouter-key
host_services:
  - name: model
    port: 11434
ingress:
  - name: api
    port: 8000
    path_prefix: /api
    auth: token
policy:
  allow:
    - openrouter.ai
    - "*.openrouter.ai"
```

## Next steps

- Validate the yaml without starting it: `brig cell preflight mycell.yaml`.
- Build a custom image inside the VM: `brig image build ./mycell --tag localhost/my-agent:latest`.
- Trace requests from the cell: `brig cell network my-agent --tail 20`.
- For ingress + host-service end-to-end:
  [host-an-agent.md](host-an-agent.md).
- Full field reference: [cell-definition.md](../design/cell-definition.md).
