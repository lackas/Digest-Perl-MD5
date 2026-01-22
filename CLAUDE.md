# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Digest::Perl::MD5 is a pure-Perl implementation of the MD5 hashing algorithm. It provides the same interface as Digest::MD5 but without requiring compiled C code. This makes it suitable for environments without a C compiler, hashing small data (like passwords), or educational purposes.

## Build and Test Commands

```bash
# Generate Makefile (standard Perl module build)
perl Makefile.PL

# Build the module
make

# Run the test suite
make test

# Run tests directly without make
perl test.pl
```

## Project Structure

- `lib/Digest/Perl/MD5.pm` - The main module implementing MD5 in pure Perl
- `test.pl` - Main test suite with 9 tests covering functional and OO interfaces
- `tools/md5` - BSD-compatible md5 command-line tool in pure Perl
- `tools/md5-test.pl` - Comparative testing against Digest::MD5
- `tools/md5-bench.pl` - Benchmarking script
- `rand.f` - Random test data file used by test.pl

## Architecture

The module uses `use integer` for performance and implements:
- **Procedural interface**: `md5()`, `md5_hex()`, `md5_base64()` functions
- **OO interface**: `new()`, `add()`, `addfile()`, `digest()`, `hexdigest()`, `b64digest()`, `clone()`, `reset()`

The MD5 round functions (FF, GG, HH, II) are defined in the `__DATA__` section and dynamically compiled at module load time via `gen_code()` which uses `eval` to generate optimized `round()` subroutine. This handles differences between 32-bit and 64-bit architectures by applying appropriate bitmasks.

## Benchmarking

Run `tools/md5-bench.pl` to compare performance against Digest::MD5 (C implementation). The pure Perl version is ~60-100x slower than C, varying by architecture.

## Performance Notes

The code generation approach is already well-optimized:
- The 64 round operations are expanded at load time (no runtime code generation overhead)
- `rotate_left` is inlined directly into the generated code
- `use integer` forces integer arithmetic throughout

The hot path is the generated `round()` function (64 operations per 64-byte block). Single-call overhead like `padding()` is negligible.

## Optimization Research (January 2026, Claude Opus 4.5)

### What's Already Optimized

The F and G functions already use **Colin Plumb's optimizations** (1993):
- F: `z ^ (x & (y ^ z))` instead of RFC's `(x & y) | (~x & z)`
- G: `y ^ (z & (x ^ y))` instead of RFC's `(x & z) | (y & ~z)`

These avoid AND-NOT operations. The commented-out RFC versions are preserved in `gen_code()`.

### Optimizations That DON'T Help in Perl

Tested and found slower (opposite of C/assembly behavior):

1. **G function with ADD instead of OR**: `((d & b) + (~d & c))` - 10% slower in Perl due to extra NOT and masking overhead

2. **I function using subtraction**: `-d - 1` instead of `~d` - 7% slower in Perl; the `~` operator is a single opcode

3. **Inlining `padding()` into `md5()`**: negligible gain (~noise); padding runs once per hash, not in hot loop

4. **Scalar variables instead of `@X` array**: no measurable difference

5. **Eliminating `round()` function call**: ~2% gain, not worth the code complexity

### Optimization That DOES Help (Applied)

**Reduced 64-bit masking** - 11% improvement:

On 64-bit systems, results must be masked to 32 bits (`& 0xFFFFFFFF`). Original code masked twice per round (128 masks per block). Optimized to mask only:
- Once before rotate (required for correct bit shifting)
- Four times at `round()` return (final values)

This reduces masks from 128 to 68 per 64-byte block.

### Benchmark Results

- Baseline (before optimization): ~88,000-89,000 ops/sec
- After reduced masking: ~98,000-99,000 ops/sec
- Improvement: ~11%

### Future Optimization Ideas to Explore

1. **Short data constant folding**: For inputs < 64 bytes, initial constants could be pre-merged (requires API changes)

2. **H function intermediate reuse**: Pre-compute XOR results across H-rounds to eliminate MOV-equivalent operations

3. **32-bit mode**: On true 32-bit Perl, masking is skipped entirely (already implemented via `$MSK` check)

### References

- https://github.com/animetosho/md5-optimisation - detailed MD5 optimization analysis
- https://openwall.info/wiki/people/solar/software/public-domain-source-code/md5 - Colin Plumb optimizations
- https://www.nayuki.io/page/fast-md5-hash-implementation-in-x86-assembly - assembly techniques (mostly not applicable to Perl)
