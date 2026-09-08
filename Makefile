# VEXOR Makefile
#
# Primary targets:
#   make install   — build + install into your GOPATH/bin (must be on PATH)
#   make build     — build ./vexor inside the repository (developers)
#   make test      — unit + acceptance suite

GO ?= go
BIN := vexor
PKG := ./cmd/vexor

.PHONY: build install test acceptance clean

build:
	$(GO) build -o $(BIN) $(PKG)

install:
	$(GO) install $(PKG)
	@echo "installed: $$(go env GOPATH)/bin/$(BIN)"
	@echo "ensure PATH includes: export PATH=\$$PATH:$$($(GO) env GOPATH)/bin"

test:
	$(GO) test ./...
	python3 tests/acceptance.py

acceptance:
	python3 tests/acceptance.py

clean:
	rm -f $(BIN)
	rm -rf build
