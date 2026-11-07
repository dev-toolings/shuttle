# DeployShuttle dev shortcuts. Run `make help` for the list, grouped by section.

.DEFAULT_GOAL := help

C_SECTION := \033[1;33m
C_TARGET  := \033[36m
C_OK      := \033[32m
C_WARN    := \033[33m
C_ERR     := \033[31m
C_RESET   := \033[0m

# ─── Help ─────────────────────────────────────────────────────────────────

.PHONY: help
help: ## List available targets, grouped by section
	@awk -v sec="$(C_SECTION)" -v tgt="$(C_TARGET)" -v rst="$(C_RESET)" ' \
	  /^# ─── / { \
	    title = $$0; sub(/^# ─── /, "", title); sub(/ ─+$$/, "", title); \
	    printf "\n%s%s%s\n", sec, title, rst; next \
	  } \
	  /^[a-zA-Z0-9_-]+:.*## / { \
	    name = $$0; sub(/:.*/, "", name); \
	    desc = $$0; sub(/^[^#]*## /, "", desc); \
	    printf "  %s%-16s%s %s\n", tgt, name, rst, desc \
	  }' $(MAKEFILE_LIST)

# ─── Install / Setup ──────────────────────────────────────────────────────

.PHONY: install
install: ## Install the CLI built from this tree into ~/.local/bin (PREFIX to override)
	sh scripts/install-local.sh

# ─── Go CLI (app/go-cli) ──────────────────────────────────────────────────

.PHONY: go-fmt
go-fmt: ## Format all Go sources with gofmt
	cd app/go-cli && gofmt -w .

.PHONY: go-vet
go-vet: ## Run go vet
	cd app/go-cli && go vet ./...

.PHONY: go-test
go-test: ## Run the Go test suite
	cd app/go-cli && go test ./...

.PHONY: go-run
go-run: ## Run the shuttle CLI locally
	cd app/go-cli && go run ./cmd/shuttle

# ─── Build / Check ────────────────────────────────────────────────────────

.PHONY: test
test: ## Fast checks: gofmt, vet, Go tests, shell contracts
	cd app/go-cli && test -z "$$(gofmt -l .)" && go vet ./... && go test ./...
	sh scripts/test.sh

.PHONY: test-fast
test-fast: ## Fast checks: gofmt, vet, sharded Go tests, shell contracts
	cd app/go-cli && test -z "$$(gofmt -l .)" && go vet ./...
	scripts/go-test-sharded.sh
	sh scripts/test.sh

.PHONY: ci
ci: ## Run the GitHub CI workflow locally with ci-local before pushing
	@if sh scripts/ci-local.sh; then \
	  printf "$(C_OK)[make] local CI passed$(C_RESET)\n"; \
	else \
	  printf "$(C_ERR)[make] local CI failed: run 'ci-local explain' for the log tail$(C_RESET)\n"; exit 1; \
	fi

.PHONY: go-build
go-build: ## Cross-compile the shuttle binaries into dist/
	sh scripts/build-go.sh

.PHONY: build
build: ## Build the shuttle binaries + release manifest (dist/)
	sh scripts/build-go.sh

# ─── Release ──────────────────────────────────────────────────────────────

.PHONY: release
release: ## Tag and push a release (usage: make release patch|minor|major|vX.Y.Z)
	sh scripts/release.sh $(filter-out $@,$(MAKECMDGOALS))
