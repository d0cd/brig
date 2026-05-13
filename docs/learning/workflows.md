# Common Workflows

## Analyze untrusted code

```bash
# Air-gapped — no network access at all.
brig run --network none python:3.12 python suspicious_script.py

# With restricted network — only allow specific API.
brig run --policy-allow 'api.target.com' python:3.12 python fetch_and_analyze.py
```

## Run a scraper with secrets

```bash
brig secrets add api-key
brig run --name scraper --secret api-key --profile supervised \
    python:3.12 python scrape.py
brig logs scraper
brig cp scraper:/work/results.json ./results.json
brig rm scraper
```

## Long-running background cell

```bash
brig run --name worker -d --timeout 1h --profile dev python:3.12 bash
brig exec worker -- python process.py
brig files worker
brig cp worker:/work/output.csv ./
brig stop worker
brig rm worker
```

## Agent SDK usage

```python
from brig import Brig

b = Brig()
result = b.execute_sync(
    "python:3.12",
    ["python", "-c", "import json; print(json.dumps({'status': 'ok'}))"],
    timeout="30s",
    network="none",
)
print(result.stdout)  # {"status": "ok"}
```

## Daily operations

```bash
brig up          # start VM + warden
brig list        # see running cells
brig verify      # check security invariants
brig down        # stop everything
brig down --vm   # also stop the VM
```

## Policy management

```bash
brig policy show                                # global policy
brig policy set global --allow '*.example.com'  # add to allowlist
brig policy set mycell --deny 'evil.com'        # per-cell deny
brig policy show mycell --effective             # merged view
```

## Troubleshooting

```bash
brig health          # check VM + proxy status
brig verify          # check all 9 security invariants
brig diagnose mycell # inspect a specific cell
brig inspect mycell  # raw container details
```
