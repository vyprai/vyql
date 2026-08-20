# VyQL dev Makefile. The scanner is `vyql`; the security knowledge it evaluates
# — ontology, bindings, rule packs, taxonomy — is data under $VYQL_HOME or
# ./vyql, loaded at runtime rather than compiled in. When ./vyql is absent,
# fetch it with `make fetch-definitions` (same script CI uses).
#
#   make build                 # build the binaries into bin/
#   make fetch-definitions     # free with-tests bundle into ./vyql
#   make test                  # full suite (never cached — see below)
#   make lint                  # gofmt check, go vet, golangci-lint
#   make ci                    # everything the PR pipeline runs
#
# Binaries go to bin/ and never to the repository root: a root-level `vyql`
# binary would collide with the data directory name.

HOME_DIR := ./vyql
GO       := go

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build vyql and gen-ontology-json into bin/
	$(GO) build -o bin/vyql ./cmd/vyql
	$(GO) build -o bin/gen-ontology-json ./cmd/gen-ontology-json

.PHONY: tools
tools: ## Install the dev tooling this Makefile expects
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.1
	$(GO) install github.com/google/go-licenses@latest

.PHONY: fmt
fmt: ## Format all Go source
	gofmt -w .

.PHONY: lint
lint: ## gofmt check, go vet and golangci-lint
	@out="$$(gofmt -l .)"; \
	 if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	golangci-lint run

# -count=1 is mandatory, not a preference: the Go test cache keys on source and
# does not track the .vyql data files, so a cached pass can hide a change to the
# security knowledge base entirely. A bare `go test` in this repo is a bug.
.PHONY: fetch-definitions
fetch-definitions: ## Download free definitions with tests into ./vyql
	./scripts/fetch-free-definitions.sh --with-tests ./vyql

.PHONY: test
test: ## Run the full Go test suite (never cached)
	$(GO) test -count=1 ./...

.PHONY: hygiene
hygiene: ## Run the publication hygiene checks
	./scripts/check-hygiene.sh

.PHONY: notices
notices: ## Regenerate THIRD_PARTY_NOTICES.md
	./scripts/gen-third-party-notices.sh

.PHONY: ci
ci: lint test hygiene ## Everything the PR pipeline runs

.PHONY: scan
scan: build ## Scan a path: make scan PATH_TO_SCAN=/some/repo
	@test -n "$(PATH_TO_SCAN)" || { echo "usage: make scan PATH_TO_SCAN=/some/repo"; exit 1; }
	VYQL_HOME=$(HOME_DIR) ./bin/vyql scan $(PATH_TO_SCAN)

.PHONY: clean
clean: ## Remove built binaries
	rm -rf bin
