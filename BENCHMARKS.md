# Bulk-read benchmark and profile — 2026-10-09

This benchmark measures the reader separately from the filesystem mount and from
its host's file cache. It uses disposable, fsck-checked ext4 images containing a
64 MiB deterministic, nonzero payload. One image uses extents; the other uses
classic direct/indirect block maps. No real disk or global cache is modified.

## Reader results on Intel Sequoia

Platform: macOS 15.8.1, macFUSE 5.4.0, e2fsprogs 1.47.4, optimized `-O2` build.
Baseline: release `v0.2.9` (`edcbceb`). Changed reader: the bounded classic-map run
coalescing included in `v0.2.10`. The same fixtures, tools, request sizes and
three-sample procedure were used before and after the change.

| Classic-map request | Before MiB/s | After MiB/s | Before preads | After preads |
|---|---:|---:|---:|---:|
| 4 KiB | 989 | 969 | 64,488 | 64,488 |
| 64 KiB | 1,450 | 5,035 | 49,128 | 4,077 |
| 1 MiB | 1,445 | 7,234 | 48,168 | 297 |

Throughput is the median of three **warm-cache** samples. Pread counts cover one
64 MiB pass, including inode and mapping reads. These are cache/CPU/system-call
measurements, not SSD, USB or cold-disk speeds. Small timing differences in paths
with unchanged I/O counts are not established regressions or improvements. For
example, the extent path's 1 MiB requests still make 128 preads before and after,
while its measured rates vary from 8,229 to 7,067 MiB/s between runs.

At 64 KiB, the classic baseline makes 31,720 four-byte pointer reads and 16,384
four-KiB data reads, plus inode reads. A five-second `sample` profile places most
samples in `pread` through indirect mapping and payload reads. Coalescing replaces
individual leaf-pointer reads with one checked leaf read and batches contiguous
data. There is no mutable mapping cache. Holes, physical discontinuities and
pointer-array boundaries stop a run; invalid requested pointers still fail.
Single-block requests retain the small-pointer-read path and avoid lookahead.

The reference `libext2fs` reader measured 2,672 MiB/s on the classic 64 KiB case
before and 2,574 MiB/s after; raw host-file reads measured 8,806 and 7,471 MiB/s.
These paths use different mapping/checksum/cache strategies and are context,
not claims of equivalence to Linux's native ext4 driver.

Full sample ranges, syscall counts, raw/reference results and cached-inode
(`snapshot`) diagnostics are in [before](benchmarks/2026-10-09-sequoia-before.json)
and [after](benchmarks/2026-10-09-sequoia-after.json). The production callback
still loads and verifies its inode on every read; `snapshot` is a diagnostic only.

## Mounted macFUSE results

The baseline daemon delivers a first-pass 64 MiB transfer in **16,384 callbacks,
all 4 KiB**, even when the application requests 64 KiB or 1 MiB at a time.
First-pass transfers were about 42–48 MiB/s. Warm mounted-file-cache transfers
were about 7–8 GiB/s and do not measure repeated reader work. With macFUSE's
`noubc,noreadahead` options, repeated reads stayed about 45–48 MiB/s.

The changed mapping path does not improve a 4 KiB callback. Therefore the reader
speedups above must not be presented as mounted-transfer speedups. The native
first-pass/cache-disabled results remain subject to the callback-size/IPC limit.
The documented `iosize=1048576` option did not change the observed callback sizes
in this setup. Profiling-daemon experiments with per-file direct I/O and matched
session/connection maximum-read settings also retained 4 KiB callbacks; production
mount defaults were not changed. The cause needs provider-level investigation.

See the [macFUSE mount-option documentation](https://github.com/macfuse/macfuse/wiki/Mount-Options)
for cache and I/O-size options. This benchmark does not recommend disabling caches
for normal use. Raw baseline measurements are in
[mounted-before](benchmarks/2026-10-09-sequoia-mounted-before.json).

## Reproduce

Put e2fsprogs' `sbin` in PATH. Clean when changing optimization/sanitizer flags.
The helper reference is compiled using e2fsprogs' `ext2fs` pkg-config metadata.

```sh
make clean
make -j2 test/bulk-reader CFLAGS=-O2
python3 test/bulk-benchmark.py --output /tmp/bulk-benchmark.json
```

Initialization/open time is excluded. Each path is warmed before timing; mode
order rotates across samples. Timing loops do not hash data or write output.
Separate SHA-256 checks compare the reader and debugfs extraction with the host
payload. Source images must remain unchanged. No timing threshold is a CI gate.
The I/O instrumentation is confined to the benchmark helper, not production code.

To retain fixtures for macOS mount measurements, use a new disposable directory:

```sh
python3 test/bulk-benchmark.py --fixtures /tmp/ext4-bulk-fixtures --output /tmp/bulk.json
make -j2 CFLAGS=-O2
python3 test/mount-bulk.py --fixtures /tmp/ext4-bulk-fixtures --output /tmp/mounted.json
make test/bulk-mount-profile CFLAGS=-O2
READER=./test/bulk-mount-profile python3 test/mount-bulk.py \
  --fixtures /tmp/ext4-bulk-fixtures --output /tmp/profile.json --samples 1
```

The mount profiler reports actual daemon callback sizes. Client pread counters
on mounted files count application requests, not backing-image I/O. Retained
fixtures can be removed after all mounts are gone. Failed mount fixtures are
kept for inspection rather than deleted through an active mount.

On Linux, `--native-linux` adds native ext4 reads of the same payload via
explicitly created, read-only loop devices and `ro,noload` mounts. It requires
sudo; only disposable fixtures are mounted. Devices are detached after use and
image hashes must remain unchanged. The separate optimized CI benchmark job saves
`linux-bulk-benchmark` JSON, including the native comparison. CI runner timings
are environment-specific and are not measurements of the user's hardware.

The old FreeBSD crash/throughput reports still require native FreeBSD validation.
A benchmark on Intel Sequoia or a Linux CI runner does not reproduce those reports.
