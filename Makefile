.PHONY: setup test check smoke clean reset help up down bench

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# --- Getting started (two commands) ---

setup: .venv ## Install brig, create VM, start everything
	uv pip install -e ".[dev]"
	@$(MAKE) _copy-addons
	uv run brig init 2>/dev/null || true
	@if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -q '^brig$$'; then \
		echo "Creating VM (this takes a few minutes on first run)..."; \
		limactl create --name=brig ~/.brig/lima.yaml; \
	fi
	@if ! limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q '^brig Running'; then \
		echo "Starting VM..."; \
		limactl start brig; \
	fi
	./scripts/provision-vm.sh
	uv run brig up
	@echo ""
	@echo "Ready. Try: uv run brig run alpine echo hello"

up: ## Start VM + warden (if already set up)
	uv run brig up

down: ## Stop all cells + warden
	uv run brig down

# --- Testing ---

test: ## Run unit tests (no VM needed)
	uv run pytest tests/ -q -m "not slow" --ignore=tests/benchmarks

check: ## Run full CI checks locally
	uv run ruff check src/ tests/
	uv run mypy src/brig/ --ignore-missing-imports --follow-imports=silent
	uv run pytest tests/ -q -m "not slow" --ignore=tests/benchmarks --cov=src --cov-fail-under=70

smoke: ## Run end-to-end smoke test (requires VM)
	./scripts/local-smoke-test.sh

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

_copy-addons:
	@mkdir -p ~/.brig/cells/addons
	@cp src/addons/enforce.py src/addons/logger.py src/addons/ops.py ~/.brig/cells/addons/
	@for f in src/addons/canary.py src/addons/signer.py src/addons/notifier.py src/addons/summarizer.py; do \
		[ -f "$$f" ] && cp "$$f" ~/.brig/cells/addons/ || true; \
	done
