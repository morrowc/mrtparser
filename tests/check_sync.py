#!/usr/bin/env python3
import json
import subprocess
import sys
import os
from pathlib import Path

def run_parser(binary, args):
    try:
        result = subprocess.run([binary] + args, capture_output=True, text=True, check=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error running {binary}: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return None

def compare_json_lines(rust_lines, cpp_lines):
    if len(rust_lines) != len(cpp_lines):
        print(f"Mismatch in record count: Rust={len(rust_lines)}, C++={len(cpp_lines)}")
        return False

    success = True
    for i, (r_line, c_line) in enumerate(zip(rust_lines, cpp_lines)):
        try:
            r_json = json.loads(r_line)
            c_json = json.loads(c_line)
            if r_json != c_json:
                print(f"Mismatch in record {i+1}:")
                # We could do a more detailed diff here if needed
                print(f"  Rust: {r_line}")
                print(f"  C++:  {c_line}")
                success = False
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON at record {i+1}: {e}")
            print(f"  Line: {r_line if 'Rust' in str(e) else c_line}")
            success = False
    
    return success

def main():
    repo_root = Path(__file__).parent.parent.absolute()
    rust_bin = repo_root / "rust" / "target" / "debug" / "mrtparser"
    cpp_bin = repo_root / "build" / "mrtparser"
    test_data_dir = repo_root / "testdata"

    if not rust_bin.exists():
        print(f"Rust binary missing: {rust_bin}. Run 'cargo build' in rust/ directory.")
        sys.exit(1)
    if not cpp_bin.exists():
        print(f"C++ binary missing: {cpp_bin}. Run 'cmake .. && make' in build/ directory.")
        sys.exit(1)

    mrt_files = list(test_data_dir.glob("*.bz2")) + list(test_data_dir.glob("*.gz")) + list(test_data_dir.glob("*.mrt"))
    if not mrt_files:
        print(f"No test data found in {test_data_dir}")
        sys.exit(1)

    all_passed = True
    for mrt_file in mrt_files:
        print(f"Comparing implementations on {mrt_file.name}...")
        rust_out = run_parser(str(rust_bin), ["--json", str(mrt_file)])
        cpp_out = run_parser(str(cpp_bin), ["--json", str(mrt_file)])

        if rust_out is None or cpp_out is None:
            all_passed = False
            continue

        if compare_json_lines(rust_out, cpp_out):
            print(f"  SUCCESS: {mrt_file.name} matches perfectly.")
        else:
            print(f"  FAILURE: Mismatch detected in {mrt_file.name}.")
            all_passed = False

    if all_passed:
        print("\nAll implementations are synchronized!")
        sys.exit(0)
    else:
        print("\nSynchronization check FAILED.")
        sys.exit(1)

if __name__ == "__main__":
    main()
