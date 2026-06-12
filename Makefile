.PHONY: setup test check smoke redteam clean reset help up down bench

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# --- Getting started (two commands) ---

setup: .venv ## Install brig, create VM, start everything
	uv pip install -e ".[dev]"
	@$(MAKE) _copy-addons
	uv run brig system init
	@if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -q '^brig$$'; then \
		echo "Creating VM (this takes a few minutes on first run)..."; \
		limactl create --name=brig ~/.brig/lima.yaml; \
	fi
	@if ! limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q '^brig Running'; then \
		echo "Starting VM..."; \
		limactl start brig; \
	fi
	./scripts/provision-vm.sh
	@echo "Building the warden image inside the VM (one-time, ~1-2 min)..."
	./scripts/build-warden-image.sh
	uv run brig system up
	@echo ""
	@echo "Ready. Try: uv run brig run alpine echo hello"

up: ## Start VM + warden (if already set up)
	uv run brig system up

down: ## Stop all cells + warden
	uv run brig system down

# --- Testing ---

test: ## Run unit tests (no VM needed)
	uv run pytest tests/ -q -m "not slow" --ignore=tests/benchmarks

check: ## Run full CI checks locally
	uv run ruff check src/ tests/
	uv run mypy src/brig/ --ignore-missing-imports --follow-imports=silent
	uv run pytest tests/ -q -m "not slow" --ignore=tests/benchmarks --cov=src --cov-fail-under=65

smoke: ## Run end-to-end smoke test (requires VM)
	./scripts/local-smoke-test.sh

redteam: ## Run the containment red-team (Tier-1, requires VM up)
	./tests/test_containment_e2e.sh

bench: ## Run benchmarks
	uv run pytest tests/benchmarks/ -m bench --benchmark-enable -q

# --- Cleanup ---

clean: ## Remove caches (keeps venv and VM)
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

reset: ## Full reset: remove venv, VM, and all state
	rm -rf .venv build/ dist/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	-limactl stop brig 2>/dev/null
	-limactl delete brig 2>/dev/null
	pip uninstall brig -y 2>/dev/null || true
	pip3 uninstall brig -y 2>/dev/null || true
	@echo "Reset complete. Run: make setup"

# --- Internal ---

.venv:
	uv venv

pin-gvisor: ## Fetch + write gVisor sha512s into scripts/provision-vm.sh (run once per bump)
	@./scripts/pin-gvisor.sh

_copy-addons:
	@mkdir -p ~/.brig/cells/addons
	@chmod 0700 ~/.brig/cells/addons
	@# Copy every *.py in src/brig/warden_addons/ — simpler than maintaining a
	@# split between "required" and "optional" sets that drifts from
	@# what warden actually loads. cp without -r since the dir is flat; explicit
	@# error if there's nothing to copy. (Ongoing drift is handled by
	@# `brig system up`; this stays for first-boot + seccomp staging.)
	@if ! ls src/brig/warden_addons/*.py >/dev/null 2>&1; then \
		echo "ERROR: no addon .py files in src/brig/warden_addons/"; exit 1; \
	fi
	@cp src/brig/warden_addons/*.py ~/.brig/cells/addons/
	@# Seccomp profiles are referenced by reconciler.build_run_command as
	@# /cells/seccomp/<name>.json inside the VM (the host's ~/.brig/cells
	@# is mounted at /cells). Without these, --seccomp-profile fails to
	@# find the profile inside the container.
	@mkdir -p ~/.brig/cells/seccomp
	@cp src/seccomp/*.json ~/.brig/cells/seccomp/
