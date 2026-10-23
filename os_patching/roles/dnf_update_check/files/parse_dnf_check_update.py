#!/usr/bin/env python3

import argparse
import json
import re
import sys
from pathlib import Path


# Common RPM architectures. A package token must end with a recognised
# architecture so a continuation line cannot be mistaken for a package.
KNOWN_ARCHES = {
    "x86_64", "noarch", "aarch64", "i686", "i586", "i386",
    "i486", "ppc64le", "ppc64", "s390x", "armv7hl",
    "armv7hnl", "armv6hl", "src", "nosrc", "riscv64",
    "loongarch64", "ia64", "alpha", "sparc64", "mips64",
}


SECURITY_INSTALLED_RE = re.compile(
    r"^Security:\s+(.+)\s+is an installed security update\.?\$",
    re.IGNORECASE,
)

SECURITY_RUNNING_RE = re.compile(
    r"^Security:\s+(.+)\s+is the currently running version\.?\$",
    re.IGNORECASE,
)


def split_package_token(token):
    """Return (package_name, architecture) or None."""
    if "." not in token:
        return None

    name, arch = token.rsplit(".", 1)

    if not name or arch not in KNOWN_ARCHES:
        return None

    if not re.fullmatch(r"[A-Za-z0-9_+.:~-]+", name):
        return None

    return name, arch


def make_package(name, arch, version, repo=""):
    return {
        "key": f"{name}|{arch}",
        "name": name,
        "arch": arch,
        "version": version,
        "repo": repo,
        "repositories": [repo] if repo else [],
    }


def classify_information_line(line):
    """
    Classify known non-package DNF informational lines.

    Returns:
      (handled, message, flags)

    handled:
      True if the line is known and should not be treated as a parser warning.

    message:
      Human-readable informational message.

    flags:
      Operational indicators derived from the line.
    """
    installed_match = SECURITY_INSTALLED_RE.match(line)
    if installed_match:
        return True, line, {
            "reboot_likely_required": True,
            "running_kernel_not_latest": False,
        }

    running_match = SECURITY_RUNNING_RE.match(line)
    if running_match:
        return True, line, {
            "reboot_likely_required": True,
            "running_kernel_not_latest": True,
        }

    return False, "", {}


def parse_output(output, rc):
    packages_by_key = {}
    warnings = []
    info_messages = []
    pending_package = None

    reboot_likely_required = False
    running_kernel_not_latest = False

    ignored_prefixes = (
        "last metadata expiration check:",
        "last check:",
        "obsoleting packages",
    )

    ignored_exact_lines = {
        "package",
        "package name",
        "name",
        "name arch version repo",
    }

    for original_line in output.splitlines():
        line = original_line.strip()

        if not line:
            continue

        if line.lower().startswith(ignored_prefixes):
            continue

        if line.lower() in ignored_exact_lines:
            continue

        handled, message, flags = classify_information_line(line)
        if handled:
            if message:
                info_messages.append(message)

            if flags.get("reboot_likely_required"):
                reboot_likely_required = True

            if flags.get("running_kernel_not_latest"):
                running_kernel_not_latest = True

            continue

        columns = line.split()

        if not columns:
            continue

        package_token = split_package_token(columns[0])

        # A package token by itself means DNF wrapped the row.
        # Record it as pending and parse its continuation next.
        if package_token and len(columns) == 1:
            if pending_package:
                warnings.append(
                    f"Package entry was not completed: {pending_package}"
                )

            pending_package = package_token
            continue

        # Complete package row: package.arch version [repository]
        if package_token and len(columns) >= 2:
            name, arch = package_token
            version = columns[1]
            repo = columns[2] if len(columns) >= 3 else ""

            package = make_package(name, arch, version, repo)
            existing = packages_by_key.get(package["key"])

            if existing is None:
                packages_by_key[package["key"]] = package
            elif repo and repo not in existing["repositories"]:
                existing["repositories"].append(repo)

            pending_package = None
            continue

        # Continuation row for a package token on the previous line.
        if pending_package:
            if len(columns) >= 2:
                name, arch = pending_package
                version, repo = columns[:2]

                package = make_package(name, arch, version, repo)
                packages_by_key[package["key"]] = package
                pending_package = None
                continue

            warnings.append(
                f"Could not parse continuation for {pending_package}: {line}"
            )
            pending_package = None
            continue

        if not line.lower().startswith(("repo ", "metadata ")):
            warnings.append(f"Unparsed output line: {line}")

    if pending_package:
        warnings.append(
            f"Package entry was not completed: {pending_package}"
        )

    if rc not in (0, 100):
        warnings.append(f"DNF returned unexpected exit code {rc}.")

    packages = sorted(
        packages_by_key.values(),
        key=lambda item: (item["name"], item["arch"]),
    )

    if rc == 100 and not packages:
        warnings.append(
            "DNF returned 100, but no package rows were parsed."
        )

    return {
        "dnf_rc": rc,
        "packages": packages,
        "warnings": warnings,
        "info_messages": info_messages,
        "parsed_count": len(packages),
        "reboot_likely_required": reboot_likely_required,
        "running_kernel_not_latest": running_kernel_not_latest,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rc", type=int, required=True)
    parser.add_argument("--input-file", required=True)
    args = parser.parse_args()

    try:
        output = Path(args.input_file).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError as exc:
        print(json.dumps({
            "dnf_rc": args.rc,
            "packages": [],
            "warnings": [f"Cannot read DNF output: {exc}"],
            "info_messages": [],
            "parsed_count": 0,
            "reboot_likely_required": False,
            "running_kernel_not_latest": False,
        }))
        return 2

    result = parse_output(output, args.rc)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

