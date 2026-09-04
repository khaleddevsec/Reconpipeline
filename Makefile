# ============================================================
# Reconpipeline Makefile
# Made by frozeniceee
# ============================================================

VERSION := v2.5.3
MODULE  := github.com/frozeniceee/Reconpipeline
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)

# Detect Go binary (prefer /usr/local/go/bin/go)
GO_PREFERRED := /usr/local/go/bin/go
ifeq ($(shell test -x $(GO_PREFERRED) && echo yes),yes)
  GO := $(GO_PREFERRED)
else
  GO := go
endif

BINARY  := reconpipeline
OUTDIR  := dist

.PHONY: all build install test vet fmt clean release

all: fmt vet test build

## build: Build the binary for the current platform
build:
	@echo "Building $(BINARY) $(VERSION) using $(GO)..."
	@mkdir -p $(OUTDIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(OUTDIR)/$(BINARY) ./cmd/reconpipeline/

## install: Install the binary to /usr/local/bin
install: build
	@echo "Installing $(BINARY) to /usr/local/bin/..."
	@install -m 755 $(OUTDIR)/$(BINARY) /usr/local/bin/$(BINARY)

## test: Run all tests
test:
	@echo "Running tests..."
	$(GO) test ./...

## vet: Run go vet
vet:
	@echo "Running vet..."
	$(GO) vet ./...

## fmt: Format source code
fmt:
	@echo "Formatting..."
	$(GO) fmt ./...

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(OUTDIR)

## release: Build release binaries for linux/amd64 and linux/arm64
release:
	@echo "Building release binaries..."
	@mkdir -p $(OUTDIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" \
		-o $(OUTDIR)/$(BINARY)-linux-amd64 ./cmd/reconpipeline/
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" \
		-o $(OUTDIR)/$(BINARY)-linux-arm64 ./cmd/reconpipeline/
	@echo "Release binaries:"
	@ls -lh $(OUTDIR)/

## tidy: Tidy go.mod
tidy:
	$(GO) mod tidy

## deps: Download module dependencies
deps:
	$(GO) mod download

## version: Print version
version:
	@echo $(VERSION)
