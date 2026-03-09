# mrtparser

[![C++](https://img.shields.io/badge/language-C%2B%2B17-blue.svg)](https://isocpp.org/)
[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![C++ Coverage](https://img.shields.io/badge/C%2B%2B%20Coverage-54.0%25-orange.svg)](#)
[![Rust Coverage](https://img.shields.io/badge/Rust%20Coverage-100%25-brightgreen.svg)](#)

A Modern MRT file parser implemented in both C++ and Rust. This tool is designed to parse MRT routing information export formats as specified in various RFCs:

- **RFC 6396**: MRT Routing Information Export Format
- **RFC 6397**: MRT BGP Routing Information Export Format with Geo-Location Extensions
- **RFC 8050**: MRT Routing Information Export Format with BGP Additional Path Extensions

> [!TIP]
> **Why two languages?** C++ for the speed and legacy, Rust for the safety and the "it just works" feeling. We aim for 100% coverage in the Rust implementation because we like our code like we like our coffee: robust and without surprises! ☕🦀

## C++ Implementation

### Dependencies
- CMake 3.10+
- A C++17 compatible compiler
- `libbz2` (bzip2 development files)
- `zlib` (zlib development files)
- GoogleTest (for running tests)
- `lcov` (for generating coverage reports)

### Building
```bash
mkdir build && cd build
cmake ..
make
```

### Testing and Coverage
```bash
cd build
make mrt_test
make coverage
```
The report is in `build/coverage_report/`.

## Rust Implementation

The Rust version provides the same feature set with a modern toolchain.

### Dependencies
- Rust 1.70+
- `cargo`

### Building
```bash
cd rust
cargo build --release
```

### Testing and Coverage
```bash
cd rust
cargo test
# For coverage (requires cargo-llvm-cov)
cargo llvm-cov
```

## Usage

Both implementations support similar CLI flags:

```bash
# C++ version
./build/mrtparser testdata/updates.20260222.1530.bz2

# Rust version
./rust/target/release/mrtparser testdata/updates.20260222.1530.bz2
```

- `--utc`: View updates with human readable UTC timestamps.
- `--single-line`: View updates as a single compact line.
