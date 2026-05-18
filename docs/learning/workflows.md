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
brig cell logs scraper
brig cell cp scraper:/work/results.json ./results.json
brig cell rm scraper
```

## Long-running background cell

```bash
brig run --name worker -d --timeout 1h --profile dev python:3.12 bash
brig cell exec worker -- python process.py
brig cell files worker
brig cell cp worker:/work/output.csv ./
brig cell stop worker
brig cell rm worker
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
brig system up          # start VM + warden
brig cell list        # see running cells
brig system verify      # check security invariants
brig system down        # stop everything
brig system down --vm   # also stop the VM
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
brig system doctor --quick          # check VM + proxy status
brig system verify          # check all 9 security invariants
brig cell diagnose mycell # inspect a specific cell
brig cell inspect mycell  # raw container details
```
