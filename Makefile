.PHONY: install install-dev init vm test check smoke clean help up down bench

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install brig + copy addons
	uv pip install -e .
	@$(MAKE) _copy-addons
	@echo "Installed. Run: make init"

install-dev: ## Install with dev dependencies (pytest, ruff, mypy)
	uv pip install -e ".[dev]"
	@$(MAKE) _copy-addons
	@echo "Installed (dev). Run: make init"

init: ## Initialize brig (~/.brig, lima.yaml, default policy)
	uv run brig init

vm: ## Create and start the Lima VM
	@if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -q '^brig$$'; then \
		echo "Creating VM..."; \
		limactl create --name=brig ~/.brig/lima.yaml; \
	fi
	@if ! limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q '^brig Running'; then \
		echo "Starting VM..."; \
		limactl start brig; \
	else \
		echo "VM already running"; \
	fi

up: vm ## Start everything (VM + warden)
	uv run brig up

down: ## Stop everything
	uv run brig down

test: ## Run unit tests
	uv run pytest tests/ -q -m "not slow" --ignore=tests/benchmarks

check: ## Run CI checks locally (ruff, mypy, pytest)
	uv run ruff check src/ tests/
	uv run mypy src/brig/ --ignore-missing-imports --follow-imports=silent
	uv run pytest tests/ -q -m "not slow" --ignore=tests/benchmarks --cov=src --cov-fail-under=70

smoke: ## Run end-to-end smoke test (requires VM)
	./scripts/local-smoke-test.sh

bench: ## Run benchmarks
	uv run pytest tests/benchmarks/ -m bench --benchmark-enable -q

clean: ## Remove build artifacts
	rm -rf build/ dist/ *.egg-info src/*.egg-info .venv
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

_copy-addons:
	@mkdir -p ~/.brig/cells/addons
	@cp src/addons/enforce.py src/addons/logger.py src/addons/ops.py ~/.brig/cells/addons/
	@for f in src/addons/canary.py src/addons/signer.py src/addons/notifier.py src/addons/summarizer.py; do \
		[ -f "$$f" ] && cp "$$f" ~/.brig/cells/addons/ || true; \
	done
