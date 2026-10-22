# ============================================================================
# Incident Investigation Tooling — Root Makefile
#
# Directory structure:
#   collectors/   New collector package (src/collectors, plugin per surface)
#   scanners/     Legacy scan/search scripts (kept until collectors replaces them)
#
# Each project owns a .venv created by `make setup`; QA tools run from it.
# ============================================================================

.SILENT:
.DEFAULT_GOAL := help

PROJECTS ?= collectors scanners
BIN := .venv/bin

# Run a command inside every project directory, stopping at the first failure.
run = for p in $(PROJECTS); do echo "==> $$p"; (cd "$$p" && $(1)) || exit 1; done

.PHONY: help
help: ## Show available targets
	printf "\nUsage:\n  make \033[36m<target>\033[0m [PROJECTS=\"collectors\"]\n\nTargets:\n"
	grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'
	printf "\n"

.PHONY: setup
setup: ## Create a virtualenv per project and install dependencies + QA tools
	$(call run,uv venv --allow-existing && uv pip install -e ".[dev]")

.PHONY: fmt
fmt: ## Format Python sources with ruff
	$(call run,$(BIN)/ruff format .)

.PHONY: lint
lint: ## Check formatting and lint with ruff
	$(call run,$(BIN)/ruff format --check . && $(BIN)/ruff check .)

.PHONY: sast
sast: ## Run Bandit SAST scan
	$(call run,$(BIN)/bandit -q -r . -x ./.venv)

.PHONY: dead
dead: ## Run Vulture dead-code scan
	$(call run,$(BIN)/vulture)

.PHONY: check
check: lint dead sast ## Run lint, dead-code, and SAST gates
