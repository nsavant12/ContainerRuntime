# Validation record

The project was built and exercised locally; no hosted CI run or external deployment is claimed.

- Portable Go unit tests passed with the race detector on macOS ARM64.
- Nine Go unit tests (plus subtests) passed as native Linux ARM64 test executables in the VM, covering config validation, extraction security/deduplication, image defaults, and PID identity rejection.
- Go static analysis passed for both the host build and Linux ARM64 source paths.
- Static Linux ARM64 and AMD64 runtime binaries were built. ARM64 was executed; AMD64 is cross-compiled and is not claimed as execution-tested on this Mac.
- Twenty Linux acceptance checks passed against the final ARM64 runtime. See `integration-results.json`; its binary/probe hashes match the delivered executables.
- Both 50- and 64-container benchmark runs met all declared thresholds and verified that every service exited and its cgroup was removed.
- Real registry smoke tests pulled Alpine and Nginx, including platform selection, image command metadata, and an eight-layer root filesystem.
- A final VM inspection found no remaining `isolate-*` cgroups. Workload namespaces and their private mounts exited with their processes.

The GitHub Actions workflow is configured to run unit tests, race detection, static analysis, Linux integration tests, and ARM64/AMD64 builds when this repository is pushed. Its results remain unverified until such a run occurs. Benchmark gates stay manual because shared CI machines have variable load.
