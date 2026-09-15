#!/usr/bin/env python3
"""Updates the C++ or Rust coverage badge in README.md from an LCOV info file."""

import argparse
from pathlib import Path
import re
import sys


def compute_coverage(lcov_path: Path) -> float:
  lf_total = 0
  lh_total = 0
  da_total = 0
  da_hit = 0

  with lcov_path.open("r", encoding="utf-8") as f:
    for line in f:
      line = line.strip()
      if line.startswith("LF:"):
        lf_total += int(line.split(":", 1)[1])
      elif line.startswith("LH:"):
        lh_total += int(line.split(":", 1)[1])
      elif line.startswith("DA:"):
        parts = line[3:].split(",")
        if len(parts) >= 2:
          da_total += 1
          if int(parts[1]) > 0:
            da_hit += 1

  if lf_total > 0:
    return (lh_total / lf_total) * 100.0
  if da_total > 0:
    return (da_hit / da_total) * 100.0
  return 0.0


def get_badge_color(cov: float) -> str:
  if cov >= 90.0:
    return "brightgreen"
  if cov >= 80.0:
    return "green"
  if cov >= 70.0:
    return "yellow"
  if cov >= 50.0:
    return "orange"
  return "red"


def update_readme(readme_path: Path, language: str, cov: float) -> bool:
  color = get_badge_color(cov)
  cov_str = f"{cov:.1f}"

  if language == "C++":
    label = "C++ Coverage"
    encoded_label = "C%2B%2B%20Coverage"
    pattern = r"\[!\[C\+\+ Coverage\]\(https://img\.shields\.io/badge/C%2B%2B%20Coverage-[0-9.]+%25-[a-z]+\.svg\)\]\(#\)"
  elif language == "Rust":
    label = "Rust Coverage"
    encoded_label = "Rust%20Coverage"
    pattern = r"\[!\[Rust Coverage\]\(https://img\.shields\.io/badge/Rust%20Coverage-[0-9.]+%25-[a-z]+\.svg\)\]\(#\)"
  else:
    raise ValueError(f"Unsupported language: {language}")

  new_badge = f"[![{label}](https://img.shields.io/badge/{encoded_label}-{cov_str}%25-{color}.svg)](#)"
  content = readme_path.read_text(encoding="utf-8")
  new_content, count = re.subn(pattern, new_badge, content)

  if count == 0:
    print(f"Warning: badge pattern for {language} not found in {readme_path}", file=sys.stderr)
    return False

  if new_content != content:
    readme_path.write_text(new_content, encoding="utf-8")
    print(f"Updated {language} coverage badge to {cov_str}% ({color})")
    return True

  print(f"{language} coverage badge already up to date ({cov_str}%)")
  return False


def main():
  parser = argparse.ArgumentParser(description="Update README coverage badge from lcov.info")
  parser.add_argument("--language", required=True, choices=["C++", "Rust"], help="Language badge to update")
  parser.add_argument("--lcov", required=True, type=Path, help="Path to lcov info file")
  parser.add_argument("--readme", default=Path("README.md"), type=Path, help="Path to README.md")
  args = parser.parse_args()

  if not args.lcov.exists():
    print(f"Error: LCOV file not found: {args.lcov}", file=sys.stderr)
    sys.exit(1)

  cov = compute_coverage(args.lcov)
  update_readme(args.readme, args.language, cov)


if __name__ == "__main__":
  main()
