BIN := bin/forti-intelligence
VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION) -X github.com/synit-io/forti-intelligence/internal/mcpserver.ServerVersion=$(VERSION)

.PHONY: build test vet fmt run

build:
	mkdir -p $(dir $(BIN))
	go build -trimpath -ldflags='$(LDFLAGS)' -o $(BIN) ./cmd/forti-intelligence

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w cmd internal

run:
	go run -ldflags='$(LDFLAGS)' ./cmd/forti-intelligence --transport http
