#!/usr/bin/env python3

from pathlib import Path
import re
import sys

FILES = [
    Path("roles/dnf_assess/templates/patch_index.html.j2"),
    Path("roles/dnf_assess/templates/patch_detail.html.j2"),
]

# Match the Jinja2 variable declaration.
VARIABLE_PATTERN = re.compile(
    r"^[ \t]*\{%[-]?\s*set\s+run_id\s*=.*?[-]?%\}[ \t]*\n?",
    re.MULTILINE,
)

# Match the JavaScript runId declaration.
JAVASCRIPT_PATTERN = re.compile(
    r"^[ \t]*const\s+runId\s*=\s*\{\{.*?run_id.*?tojson.*?\}\};[ \t]*\n?",
    re.MULTILINE,
)

# Match a run-ID display line, including its label.
DISPLAY_PATTERN = re.compile(
    r"^[ \t]*.*(?:Run ID:|run_id\s*\|\s*e|runId\s*\|\s*e).*"
    r"\n?",
    re.IGNORECASE | re.MULTILINE,
)

# Match a standalone run-ID reference line.
REFERENCE_PATTERN = re.compile(
    r"^[ \t]*patch_assessment\.run_id[ \t]*\n?",
    re.MULTILINE,
)


def main():
    failed = False

    for path in FILES:
        if not path.is_file():
            print(f"ERROR: File not found: {path}")
            failed = True
            continue

        original = path.read_text(encoding="utf-8")
        updated = original

        updated = VARIABLE_PATTERN.sub("", updated)
        updated = JAVASCRIPT_PATTERN.sub("", updated)
        updated = DISPLAY_PATTERN.sub("", updated)
        updated = REFERENCE_PATTERN.sub("", updated)

        if updated == original:
            print(f"NO CHANGE: {path}")
        else:
            backup = path.with_suffix(path.suffix + ".bak")
            backup.write_text(original, encoding="utf-8")
            path.write_text(updated, encoding="utf-8")
            print(f"UPDATED: {path}")
            print(f"BACKUP:  {backup}")

        remaining = re.findall(
            r"run_id|runId|patch_assessment\.run_id",
            updated,
            re.IGNORECASE,
        )

        if remaining:
            print(f"WARNING: Remaining run-ID references in {path}: {remaining}")

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
