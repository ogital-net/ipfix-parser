# Benchmark baseline

These numbers are the reference point against which future performance
changes are evaluated. Each entry shows the median wall-clock time and
the throughput Criterion derives from it.

If you change a parser hot path, re-run the relevant benches and update
this file in the same change, alongside any code that justifies a
regression.

## How to reproduce

```sh
cargo bench --all-features
```

Open `target/criterion/<bench>/<group>/<id>/report/index.html` for the
full Criterion report (distribution, CI, throughput).

## Environment

- **Hardware:** Apple M2 Ultra (`arm64`).
- **OS:** Darwin 25.4.0 / macOS 26.4.1.
- **Toolchain:** `rustc 1.95.0` (stable, 2026-04-14), `criterion 0.5`.
- **Build profile:** `bench` (inherits `release`; `lto = "fat"`,
  `codegen-units = 1`).
- **Date:** May 2026.

## Results

### `header_decode` — 16-byte IPFIX message header

| Bench | Median time | Throughput |
|---|---:|---:|
| `valid` | ~1.65 ns | ~9.0 GiB/s |

### `set_iter` — Set header iteration

| Bench | Median time | Throughput |
|---|---:|---:|
| `set_iter/synth_2_sets` (1 template + 1 data set, 1000 records) | ~3.0 ns | ~664 Melem/s |
| `set_iter_fixture/mikrotik` (every set in 154 captured messages) | ~309 ns | ~498 Melem/s |

### `record_iter` — Data-record iteration under a known template

| Bench | Records | Median time | Throughput |
|---|---:|---:|---:|
| `fixed_length` (12 fixed-width fields, 52 B/record) | 1000 | ~838 ns | ~60 GiB/s |
| `variable_length` (12 fixed + 1 var-length field) | 1000 | ~1.53 µs | ~653 Melem/s |

Both paths return zero-copy `DataRecord` views; no field decoding is
performed in this bench. The fixed-length path skips `record_extent`
entirely (`min_record_size` is the exact record size). The
variable-length path uses a precomputed skip table built once in
`DataRecordIter::new`, so the per-record extent walk only iterates over
varlen fields rather than every field in the template.

### `field_decode` — Full field iteration including typed accessors

| Bench | Records | Fields | Median time | Throughput |
|---|---:|---:|---:|---:|
| `walk_fields_typed` (calls `as_uXX` per field) | 1024 | 12 288 | ~24.9 µs | ~2.07 GiB/s |
| `walk_fields_raw` (touches `FieldValue` only) | 1024 | 12 288 | ~13.4 µs | ~3.84 GiB/s |

Both numbers include the header decode, set iteration, template lookup,
and per-record extent computation — i.e. everything a real consumer
does.

### `message_walk` — End-to-end fixture walk

| Bench | Messages | Bytes | Median time | Throughput |
|---|---:|---:|---:|---:|
| `mikrotik_bytes` | 154 | ~57.6 KiB | ~22.0 µs | ~2.53 GiB/s |
| `mikrotik_messages` | 154 | — | ~21.6 µs | ~7.11 Melem/s |

Each iteration replays the fixture's 154 IPFIX UDP payloads through a
fresh `HashMapTemplateStore`: header → set iteration → template
parsing/insertion → data-record/field iteration. The `HashMapTemplateStore`
allocations are included in the time.

### `decode_into` — Bulk record decode via `DecodePlan`

Synthetic Data Set with 1024 records, 12 fixed-width fields each
(54 B/record, ~54 KiB total). Every field is mapped to a contiguous slot
in a packed destination struct, so `DecodePlan::build` coalesces the 12
mappings into 6 batch byte-swap ops.

| Bench | Median time | Throughput |
|---|---:|---:|
| `decode_into_plan` (`DataRecord::decode_into`) | ~13.6 µs | ~3.79 GiB/s |
| `field_iterator_typed` (`as_uXX` per field) | ~22.7 µs | ~2.27 GiB/s |

`decode_into` is ~40 % faster than the per-field iterator. The win comes
from amortizing the iterator state machine and bounds checks over the
whole record, plus letting LLVM auto-vectorize each batched byte-swap
into NEON / SSSE3 over a contiguous slice.

An earlier revision shipped explicit `unsafe` NEON and SSSE3 intrinsics
for the swap helpers. A head-to-head microbench showed they only matched
the auto-vectorized scalar code (~46 ns per 4 KiB buffer either way), so
per `CLAUDE.md` ("Coding conventions" → unsafe) we removed them. The
decode-side API remains unchanged; the path back to explicit intrinsics
is short if a future workload justifies it.

## Notes

- `--quick` mode (Criterion sample size 10) reproduces these numbers to
  within ~3 % run-to-run on the reference hardware.
- The fixture (`tests/fixtures/mt-ipfix-flow.pcapng`) is small enough
  that everything fits in L1; the message_walk bench is therefore a
  *parser* throughput number, not a memory-bandwidth-limited number.
- No `unsafe` is currently used on the hot path. Any future SIMD or
  `unsafe` opt-in must record the new numbers here alongside the
  existing baseline (cf. **Coding conventions** in `CLAUDE.md`).
