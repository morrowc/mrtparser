# mrtparser

[![C++](https://img.shields.io/badge/language-C%2B%2B17-blue.svg)](https://isocpp.org/)
[![Coverage](https://img.shields.io/badge/coverage-39.6%25-orange.svg)](#)

A Modern MRT file parser implemented in C++. This tool is designed to parse MRT routing information export formats as specified in various RFCs:

- **RFC 6396**: MRT Routing Information Export Format
- **RFC 6397**: MRT BGP Routing Information Export Format with Geo-Location Extensions
- **RFC 8050**: MRT Routing Information Export Format with BGP Additional Path Extensions

## Dependencies

- CMake 3.10+
- A C++17 compatible compiler
- `libbz2` (bzip2 development files)
- `zlib` (zlib development files)
- GoogleTest (for running tests)
- `lcov` (for generating coverage reports)

## Building

```bash
mkdir build && cd build
cmake ..
make
```

## Testing and Coverage

To run the automated test suite and generate a coverage report:

```bash
cd build
make mrt_test
make coverage
```

The coverage report will be available in the `build/coverage_report/` directory.

## Usage

Provide an MRT file (e.g., standard, gzip, or bzip2 compressed) as an argument:

```bash
./build/mrtparser testdata/updates.20260222.1530.bz2
```
This produces multi-line output with unix-epoch seconds timestamps.
To view updates as a single line: `--single-line`.
To view updates with human readable timestamps: `--utc`.