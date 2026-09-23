#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
limactl shell isolate-dev sudo mkdir -p /opt/isolate
limactl copy bin/isolate bin/probe scripts/integration.py scripts/benchmark.py isolate-dev:/tmp/
limactl shell isolate-dev sudo sh -c 'install -m 755 /tmp/isolate /opt/isolate/isolate && modprobe overlay'
limactl shell isolate-dev sudo python3 /tmp/integration.py --binary /opt/isolate/isolate --probe /tmp/probe --output /tmp/integration-results.json
limactl shell isolate-dev sudo python3 /tmp/benchmark.py --binary /opt/isolate/isolate --probe /tmp/probe --output /tmp/benchmark-results.json --enforce
mkdir -p docs
limactl copy isolate-dev:/tmp/integration-results.json docs/integration-results.json
limactl copy isolate-dev:/tmp/benchmark-results.json docs/benchmark-results.json
