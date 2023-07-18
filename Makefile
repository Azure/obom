# Makefile for obom

# Variables

PROJECT_PKG = github.com/Azure/obom
BINARY = obom
SRC = $(wildcard *.go)
LDFLAGS = -s -w

GIT_COMMIT  = $(shell git rev-parse HEAD)
GIT_TAG     = $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
GIT_DIRTY   = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")

LDFLAGS += -X '$(PROJECT_PKG)/internal/version.GitCommit=${GIT_COMMIT}'
LDFLAGS += -X '$(PROJECT_PKG)/internal/version.GitTreeState=${GIT_DIRTY}'

.PHONY: help
help: # Display help
	@awk -F ':|##' '/^[^\t].+?:.*?##/ { printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF }' $(MAKEFILE_LIST)

.PHONY: build
build: $(SRC) ## Build the obom binary
	go build -v --ldflags="$(LDFLAGS)" -o $(BINARY) . 

# Clean up build artifacts
.PHONY: clean
clean: ## Clean the binary outputs
	rm -f $(BINARY)

# Run tests
.PHONY: test
test: ## Run tests
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage: ## Generate test coverage
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm coverage.out
