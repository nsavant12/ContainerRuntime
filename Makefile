GO ?= go
GOOS ?= linux
GOARCH ?= $(shell $(GO) env GOARCH)
BINARY := bin/isolate
PROBE := bin/probe

.PHONY: all build probe test vet integration benchmark vm-up vm-test fmt
all: build probe
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -o $(BINARY) ./cmd/isolate
probe:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -o $(PROBE) ./tests/probe
test:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
fmt:
	gofmt -w cmd internal tests
integration: all
	sudo python3 scripts/integration.py --binary $(BINARY) --probe $(PROBE)
benchmark: all
	sudo python3 scripts/benchmark.py --binary $(BINARY) --probe $(PROBE) --enforce
vm-up:
	limactl start --name=isolate-dev --vm-type=vz --cpus=4 --memory=4 --disk=16 --containerd=none --mount-none --tty=false template:ubuntu
vm-test: all
	bash scripts/vm-test.sh
