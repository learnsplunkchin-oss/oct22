
#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXTENSIONS = {".yml", ".yaml", ".j2", ".py"}
MAX_LINE_LENGTH = 160

checks = [
    ("Ansible lint", ["ansible-lint", "."]),
    ("YAML lint", ["yamllint", "."]),
]

overall_failed = False

for name, command in checks:
    print(f"\n{'=' * 60}\n{name}\n{'=' * 60}")
    try:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            overall_failed = True
    except FileNotFoundError:
        print(f"ERROR: Command not found: {command[0]}")
        overall_failed = True

print(f"\n{'=' * 60}\nLine length check: maximum {MAX_LINE_LENGTH}\n{'=' * 60}")

line_violations = 0

for path in ROOT.rglob("*"):
    if not path.is_file() or path.suffix not in EXTENSIONS:
        continue
    if ".git" in path.parts or ".venv" in path.parts or "__pycache__" in path.parts:
        continue

    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                length = len(line.rstrip("\r\n"))
                if length > MAX_LINE_LENGTH:
                    print(f"{path.relative_to(ROOT)}:{line_number}: {length} characters")
                    line_violations += 1
    except (OSError, UnicodeError) as exc:
        print(f"WARNING: Cannot read {path}: {exc}")

if line_violations:
    print(f"FAIL: {line_violations} line(s) exceed {MAX_LINE_LENGTH} characters.")
    overall_failed = True
else:
    print("PASS: No lines exceed 160 characters.")

sys.exit(1 if overall_failed else 0)
