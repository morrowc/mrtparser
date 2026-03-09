# MRT Parser Implementation Plan (C++)

## Goal

Implement a modern MRT file parser in C++ that supports RFC 6396, 6397, and 8050 (BGP Additional Paths).

## Proposed Changes

### Build System

- **[NEW] `CMakeLists.txt`**: Standard CMake configuration.
- Dependencies: `libbz2-dev` and `zlib1g-dev` for compressed file support.

### [NEW] `include/mrt_parser.h`, `src/mrt_parser.cpp`

Core logic for parsing MRT records.

- `class MrtRecord`: Represents a single MRT record.
- `class MrtParser`: Handles file reading and record extraction.
- Support for Extended Timestamp (ET) types.
- Specialized parsers for `TABLE_DUMP_V2` and `BGP4MP`.

### [NEW] `include/bgp_parser.h`, `src/bgp_parser.cpp`

Logic for parsing BGP messages.

- `class BgpMessage`: Encapsulates BGP message data.
- Utility functions for decoding BGP attributes (AS_PATH, COMMUNITIES, etc.).
- Support for 4-byte ASNs and Additional Paths (RFC 8050).

### [NEW] `src/main.cpp`

Command-line interface to:

- Read MRT files (supporting `.bz2` and `.gz` streams).
- Output record summaries to stdout.

## Verification Plan

### Automated Tests

- **Google Test (gtest)**: For unit testing individual parsing functions.
- Run against `testdata/updates.20260222.1530.bz2`.

- Compile with `make` and run `./mrtparser testdata/updates.20260222.1530.bz2`.
- Verify output against RFC examples.

### CLI and Output Enhancements

- **UTC Timestamps:** Convert Unix timestamps to human-readable UTC strings when requested.
- **Single-line Output:** Provide a compact mode where each MRT record is printed as a single line.
- **IANA Mappings:** Map numeric BGP attribute types and BGP message types to their descriptive names (e.g., `NEXT_HOP`, `UPDATE`).
- **Community Normalization:** Parse BGP `COMMUNITIES` attribute into `AS:VALUE` format (e.g., `65532:12345`).
- **Multi-file Support:** Process one or more files (or globs expanded by shell) provided as command-line arguments.
- **CI/CD Fix:** Update `lcov` flags in `CMakeLists.txt` for compatibility with GitHub Actions runners (version 1.15+).
