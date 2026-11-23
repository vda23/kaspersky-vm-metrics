GO ?= go
GOARCH ?= $(shell $(GO) env GOARCH)

.PHONY: build test test-upgrade vet package clean
build:
	CGO_ENABLED=1 GOOS=linux GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags="-s -w" -o build/$(GOARCH)/kaspersky-vm-metrics .

test:
	CGO_ENABLED=1 $(GO) test -race -coverprofile=coverage.out ./...

test-upgrade: build
	KVM_UPGRADE_BINARY="$(CURDIR)/build/$(GOARCH)/kaspersky-vm-metrics" $(GO) test -count=1 -run '^TestLiveUpgradeFromV1$$' -v .

vet:
	$(GO) vet ./...

package: build
	bash tools/package.sh $(GOARCH)

clean:
	rm -rf build dist coverage.out
