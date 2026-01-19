import os
import re
import sys


HEADER_LINE_1 = "// Copyright (c) Microsoft Corporation."
HEADER_LINE_2 = "// Licensed under the MIT License."


def should_skip_path(path: str) -> bool:
    norm = path.replace("/", "\\")
    return any(part in norm for part in ("\\target\\", "\\bin\\", "\\obj\\"))


def find_rs_files(root_dir: str) -> list[str]:
    out: list[str] = []
    for base, _, files in os.walk(root_dir):
        for name in files:
            if not name.endswith(".rs"):
                continue
            full = os.path.join(base, name)
            if should_skip_path(full):
                continue
            out.append(full)
    out.sort()
    return out


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def check_license_headers(rust_root: str) -> list[str]:
    problems: list[str] = []
    for path in find_rs_files(rust_root):
        text = read_text(path)
        lines = text.splitlines()
        if len(lines) < 2:
            problems.append(f"{path}: file too short for header")
            continue
        if lines[0] != HEADER_LINE_1 or lines[1] != HEADER_LINE_2:
            problems.append(f"{path}: missing/incorrect license header")
    return problems


TEST_ATTR_RE = re.compile(r"^\s*#\s*\[\s*test\s*\]", re.MULTILINE)

CRATE_SRC_RE = re.compile(r"\\\\native\\\\rust\\\\[^\\\\]+\\\\src\\\\", re.IGNORECASE)


def check_no_tests_in_src(rust_root: str) -> list[str]:
    problems: list[str] = []
    for base, _, files in os.walk(rust_root):
        for name in files:
            if not name.endswith(".rs"):
                continue
            full = os.path.join(base, name)
            if should_skip_path(full):
                continue
            norm = full.replace("/", "\\")
            if CRATE_SRC_RE.search(norm) is None:
                continue
            text = read_text(full)
            if TEST_ATTR_RE.search(text) is not None:
                problems.append(f"{full}: contains #[test] (tests must live under tests/)")
    return problems


def main() -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    rust_root = os.path.join(repo_root, "native", "rust")

    header_problems = check_license_headers(rust_root)
    src_test_problems = check_no_tests_in_src(rust_root)

    problems = header_problems + src_test_problems
    if not problems:
        print("OK: Rust repo rules satisfied")
        return 0

    print("FAILED: Rust repo rules not satisfied")
    for p in problems:
        print(f"- {p}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
