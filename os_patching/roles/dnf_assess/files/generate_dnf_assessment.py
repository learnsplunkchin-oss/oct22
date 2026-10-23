#!/usr/bin/env python3
"""Build normalized RHEL DNF pre-check/post-check assessment JSON."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def read_json(path):
    """Read a JSON object. Return an empty object if it cannot be read."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def find_evidence(directory, host):
    """Find evidence using supported per-host file layouts."""
    candidates = [
        os.path.join(directory, host + ".json"),
        os.path.join(directory, host, host + ".json"),
        os.path.join(directory, host, "assessment.json"),
    ]

    for path in candidates:
        if os.path.isfile(path):
            return read_json(path), path

    return {}, None


def classify(package_name):
    """Classify kernel-related RPMs; classify everything else as regular."""
    name = package_name.lower().split()[0] if package_name.strip() else ""

    if name.startswith(("kernel", "kmod")):
        return "kernel"

    return "regular"


def package_items(data):
    """Normalize package data to a list of name/label/patch_type objects."""
    raw = data.get("packages", data.get("updates", []))
    result = []

    if isinstance(raw, dict):
        raw = [
            {
                "name": key,
                "label": value if isinstance(value, str) else key,
            }
            for key, value in raw.items()
        ]

    if not isinstance(raw, list):
        raw = []

    for item in raw:
        if isinstance(item, str):
            name = item.strip()
            label = name
        elif isinstance(item, dict):
            name = str(
                item.get("name")
                or item.get("package")
                or item.get("nevra")
                or item.get("key")
                or ""
            ).strip()

            label = str(
                item.get("label")
                or item.get("nevra")
                or item.get("package")
                or name
            ).strip()
        else:
            continue

        if not name and label:
            name = label

        if name:
            result.append(
                {
                    "name": name,
                    "label": label or name,
                    "patch_type": classify(name),
                }
            )

    # Preserve original order while removing duplicate package names.
    seen = set()
    unique = []

    for item in result:
        if item["name"] not in seen:
            seen.add(item["name"])
            unique.append(item)

    return unique


def phase_data(raw, path, phase):
    """Normalize evidence for one host and one phase."""
    if not path:
        return {
            "available": False,
            "packages": [],
            "metadata": {
                "status": "MISSING",
                "phase": phase,
                "evidence_file": None,
                "package_count": 0,
                "dnf_rc": None,
                "stderr": "Evidence file not found",
            },
            "patch_counts": {"kernel": 0, "regular": 0},
        }

    packages = package_items(raw)

    metadata_source = (
        raw.get("metadata")
        if isinstance(raw.get("metadata"), dict)
        else raw
    )

    raw_count = raw.get(
        "package_count",
        raw.get("parsed_count", raw.get("count")),
    )

    try:
        count = int(raw_count) if raw_count is not None else len(packages)
    except (TypeError, ValueError):
        count = len(packages)

    kernel_count = sum(
        1 for package in packages
        if package["patch_type"] == "kernel"
    )
    regular_count = sum(
        1 for package in packages
        if package["patch_type"] == "regular"
    )

    metadata = {
        "status": str(metadata_source.get("status") or "UNKNOWN").upper(),
        "phase": metadata_source.get("phase", phase),
        "captured_at": metadata_source.get("captured_at"),
        "dnf_rc": metadata_source.get(
            "dnf_rc",
            metadata_source.get("rc"),
        ),
        "stderr": metadata_source.get("stderr") or metadata_source.get("error"),
        "kernel": metadata_source.get("kernel"),
        "os_distribution": metadata_source.get(
            "os_distribution",
            metadata_source.get("distribution"),
        ),
        "os_version": metadata_source.get(
            "os_version",
            metadata_source.get("distribution_version"),
        ),
        "package_count": count,
        "evidence_file": path,
    }

    return {
        "available": True,
        "packages": packages,
        "metadata": metadata,
        "patch_counts": {
            "kernel": kernel_count,
            "regular": regular_count,
        },
    }


def host_report(host, base_dir):
    """Compare pre-check and post-check package evidence for one host."""
    pre_raw, pre_path = find_evidence(
        os.path.join(base_dir, "pre"),
        host,
    )
    post_raw, post_path = find_evidence(
        os.path.join(base_dir, "post"),
        host,
    )

    pre = phase_data(pre_raw, pre_path, "precheck")
    post = phase_data(post_raw, post_path, "postcheck")

    pre_map = {package["name"]: package for package in pre["packages"]}
    post_map = {package["name"]: package for package in post["packages"]}

    resolved_keys = sorted(set(pre_map) - set(post_map))
    remaining_keys = sorted(set(pre_map) & set(post_map))
    new_keys = sorted(set(post_map) - set(pre_map))

    pre_status = pre["metadata"]["status"]
    post_status = post["metadata"]["status"]

    failed_statuses = {
        "FAILED",
        "FAILURE",
        "ERROR",
        "PATCH FAILED",
    }

    if not pre["available"] or not post["available"]:
        status = "INCOMPLETE"
        reason = "Pre-check or post-check evidence is missing."
    elif pre_status in failed_statuses or post_status in failed_statuses:
        status = "PATCH FAILED"
        reason = "A pre-check or post-check evidence status reports failure."
    elif post["metadata"]["package_count"] == 0:
        status = "PASS"
        reason = "No update candidates were reported by the post-check."
    else:
        status = "UPDATES REMAIN"
        reason = "The post-check reports update candidates."

    comparison = {
        "resolved": [pre_map[key] for key in resolved_keys],
        "remaining": [post_map[key] for key in remaining_keys],
        "new": [post_map[key] for key in new_keys],
        "resolved_count": len(resolved_keys),
        "remaining_count": len(remaining_keys),
        "new_count": len(new_keys),
    }

    return {
        "host": host,
        "status": status,
        "reason": reason,
        "precheck": pre,
        "postcheck": post,
        "patch_counts": {
            "precheck": pre["patch_counts"],
            "postcheck": post["patch_counts"],
        },
        "comparison": comparison,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate a normalized DNF assessment JSON file."
    )
    parser.add_argument("--base-dir", required=True)
    parser.add_argument(
        "--expected-hosts",
        required=True,
        help="Comma-separated host names",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--collector-host", default="localhost")
    args = parser.parse_args()

    hosts = list(
        dict.fromkeys(
            host.strip()
            for host in args.expected_hosts.split(",")
            if host.strip()
        )
    )

    if not hosts:
        print(
            "ERROR: --expected-hosts did not contain any host names",
            file=sys.stderr,
        )
        return 1

    reports = [
        host_report(host, args.base_dir)
        for host in hosts
    ]

    summary = {
        "hosts": len(reports),
        "pass": sum(
            report["status"] == "PASS"
            for report in reports
        ),
        "updates_remain": sum(
            report["status"] == "UPDATES REMAIN"
            for report in reports
        ),
        "patch_failed": sum(
            report["status"] == "PATCH FAILED"
            for report in reports
        ),
        "incomplete": sum(
            report["status"] == "INCOMPLETE"
            for report in reports
        ),
        "review": sum(
            report["status"] == "REVIEW"
            for report in reports
        ),
        "precheck_candidates": sum(
            report["precheck"]["metadata"]["package_count"]
            for report in reports
            if report["precheck"]["available"]
        ),
        "postcheck_candidates": sum(
            report["postcheck"]["metadata"]["package_count"]
            for report in reports
            if report["postcheck"]["available"]
        ),
        "precheck_kernel": sum(
            report["patch_counts"]["precheck"]["kernel"]
            for report in reports
        ),
        "precheck_regular": sum(
            report["patch_counts"]["precheck"]["regular"]
            for report in reports
        ),
        "postcheck_kernel": sum(
            report["patch_counts"]["postcheck"]["kernel"]
            for report in reports
        ),
        "postcheck_regular": sum(
            report["patch_counts"]["postcheck"]["regular"]
            for report in reports
        ),
        "resolved_candidates": sum(
            report["comparison"]["resolved_count"]
            for report in reports
        ),
        "remaining_candidates": sum(
            report["comparison"]["remaining_count"]
            for report in reports
        ),
        "new_candidates": sum(
            report["comparison"]["new_count"]
            for report in reports
        ),
    }

    summary["attention_required"] = (
        summary["updates_remain"]
        + summary["patch_failed"]
        + summary["incomplete"]
        + summary["review"]
    )

    document = {
        "generated_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "collector_host": args.collector_host,
        "summary": summary,
        "hosts": reports,
    }

    output_dir = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(output_dir, exist_ok=True)

    temporary_path = args.output + ".tmp"

    with open(temporary_path, "w", encoding="utf-8") as handle:
        json.dump(
            document,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    os.replace(temporary_path, args.output)

    print(json.dumps(summary, indent=2))

    # rc 2 means the report was generated but attention is required.
    return 2 if summary["attention_required"] else 0


if __name__ == "__main__":
    sys.exit(main())
