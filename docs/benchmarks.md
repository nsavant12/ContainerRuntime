# Measured performance

These are measurements of this implementation, taken on September 6, 2026, inside the dedicated Lima VM: **4 vCPUs, 4 GiB configured RAM, Linux 7.0.0-28-generic, aarch64**. The runtime and test workload were statically compiled with Go 1.27.1 on macOS. The stored reports include SHA-256 hashes matching the delivered ARM64 binaries.

| Measurement | 50-container run | 64-container run |
|---|---:|---:|
| Warm starts measured, after 5 warmups | 100 | 100 |
| Runtime startup p50 | 3.88 ms | 4.49 ms |
| Runtime startup p95 | 4.41 ms | 5.16 ms |
| Runtime startup maximum | 4.57 ms | 5.59 ms |
| CLI launch through workload exit/cleanup p95 | 8.37 ms | 9.97 ms |
| Simultaneously live containers | 50 | 64 |
| Successful service requests | 1,000 / 1,000 | 1,280 / 1,280 |
| Concurrent request p95 | 1.94 ms | 2.06 ms |
| Single-service request p95 | 0.211 ms | 0.196 ms |
| Allocated layer-storage reduction | 97.87% | 98.31% |

Evidence: [50-container report and raw startup samples](benchmark-results.json), [64-container report and raw startup samples](benchmark-64-results.json), [20 passing Linux acceptance tests](integration-results.json), and [registry image smoke tests](registry-results.json). Both performance runs passed every declared target and verified cleanup. Alpine and an eight-layer Nginx image were pulled and executed separately; the performance workload uses a controlled local rootfs to make the experiment reproducible.

## What startup measures

The internal `startup_ms` timer begins at runtime entry, before image resolution, instance creation, cgroup configuration, namespace creation, mounts, pivot, privilege setup, and application exec. It ends when the parent receives PID 1's acknowledgement of a successful exec. The process may still be initializing its application logic at that point.

The second timer is deliberately broader: Python starts the CLI, waits for the probe's `READY` output and process exit, and includes runtime cleanup. This also stayed below 100 ms at p95. Image pulls/imports, compilation, cold filesystem caches, and production application readiness are excluded. Each sample creates a new cgroup, namespace set, and upper/work directories; no container is reused. Samples are sequential, after five warmups. Percentiles use the nearest-rank method.

## What concurrency measures

Every service is an independent live container with a private writable layer, namespaces, and a `.25`-core / 64 MiB / 64-task ceiling. All 50 or 64 services remain alive simultaneously. Each request performs 16 SHA-256 hashes of a 4 KiB buffer and replies `OK`. The harness sends one request per container in each of 20 bursts, separated by 20 ms. Request/response transport is attached stdin/stdout, **not TCP or HTTP**. Images and workloads are intentionally identical.

The host is not oversubscribed with sustained CPU work by this small request workload. Per-container quotas are ceilings, not reserved capacity. Separate integration workloads verify actual CPU throttling, memory OOM enforcement, and process creation limits.

“Without performance degradation” is not literally established: the measured request p95 increased about **9.2× at 50 containers** and **10.5× at 64 containers** relative to the single-service sample, while remaining around 2 ms and producing zero errors. Host scheduling and the Python harness contribute to those measurements. The supported claim is that 64 simultaneous lightweight workloads met the explicit 50 ms p95 acceptance budget, not that arbitrary workloads have identical latency or unbounded scalability.

These runs are short functional performance experiments, not long soak tests. They do not establish production throughput, cold-start performance, noisy-neighbor resistance, or long-term resource stability.

## What storage measures

The test image consists of the static probe and a real, nonsparse 16 MiB payload. The harness sums `st_blocks * 512` for the shared lower layer and per-container upper/work directories, counting each inode once. It does not use logical file sizes or assume a target reduction.

```text
actual       = shared_lower + sum(instance_upper_and_work)
full_copy    = N * shared_lower + sum(instance_upper_and_work)
reduction    = 1 - actual / full_copy
```

At 64 containers, measured allocation was **23,224,320 bytes**, compared with **1,370,750,976 bytes** under this full-copy accounting model, a **98.31%** reduction. The comparison models independent full copies of the same base; it does not create 64 physical copies or compare against filesystem reflinks, deduplication, Docker, or containerd. Download caches, retained archive staging, runtime metadata/logs, and in-memory tmpfs allocation are excluded. Heavy copy-on-write mutations would reduce the savings.

## Reproduce

On a Linux host satisfying the requirements:

```sh
make all
sudo python3 scripts/integration.py
sudo python3 scripts/benchmark.py --enforce
sudo python3 scripts/benchmark.py --concurrency 64 --output docs/benchmark-64-results.json --enforce
```

On the configured Mac:

```sh
make vm-test
limactl shell isolate-dev sudo python3 /tmp/benchmark.py --binary /opt/isolate/isolate --probe /tmp/probe --concurrency 64 --output /tmp/benchmark-64-results.json --enforce
limactl copy isolate-dev:/tmp/benchmark-64-results.json docs/benchmark-64-results.json
```

`--enforce` returns nonzero if any target or final cleanup check fails. Regenerated measurements will differ; retain the machine description and binary hashes when comparing runs. Timing gates are deliberately excluded from shared GitHub Actions runners.

## Resume wording supported by the evidence

- Developed a custom Go container runtime using Linux namespaces, cgroup v2, and a capability/seccomp policy to isolate and execute workloads.
- Enforced CPU, memory, and process limits and validated 64 simultaneous lightweight workloads with 1,280 successful requests and 2.06 ms p95 request latency on a 4-vCPU Linux VM.
- Implemented shared OverlayFS image layers, achieving 5.16 ms p95 warm startup and 98.31% lower allocated layer storage than a duplicated-base comparison across 64 instances.

Keep the workload and measurement context available when discussing these figures in an interview. The original under-100-ms and 80%-storage targets are exceeded in this experiment; a universal no-degradation claim should be replaced with the measured result.
