#!/usr/bin/env python3
"""CLI entry point for the security auditing tool."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from file_monitor import FileMonitor
from network_scanner import NetworkScanner


def generate_text_report(report_data: dict[str, Any]) -> str:
    lines = [
        "=" * 72,
        f"SECURITY AUDIT REPORT - {datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')}",
        "=" * 72,
    ]

    file_section = report_data.get("file_monitor")
    if file_section:
        lines += ["", "--- FILE INTEGRITY MONITORING (FIM) ---"]
        status = file_section.get("status", "UNKNOWN")
        lines.append(f"Audit Status: {status}")

        if status in {"CHANGED", "WARNING", "ERROR"}:
            lines.append("SECURITY ALERT: Integrity check requires attention.")

        for title, key, marker in (
            ("ADDED/NEW FILES", "added", "[+]"),
            ("MODIFIED FILES", "modified", "[!]"),
            ("DELETED FILES", "deleted", "[-]"),
        ):
            items = file_section.get(key, [])
            lines.append(f"\n{marker} {title} ({len(items)}):")
            if not items:
                lines.append("  None.")
            elif key == "added":
                for path, digest in items:
                    lines.append(f"  -> {path} (SHA256: {digest[:12]}...)")
            elif key == "modified":
                for path, old_digest, new_digest in items:
                    lines.append(f"  -> {path}")
                    lines.append(f"     OLD: {old_digest[:12]}...")
                    lines.append(f"     NEW: {new_digest[:12]}...")
            else:
                for path in items:
                    lines.append(f"  -> {path}")

        errors = file_section.get("errors", [])
        if errors:
            lines.append(f"\n[!] HASH/ACCESS ERRORS ({len(errors)}):")
            for item in errors:
                lines.append(f"  -> {item['path']}: {item['error']}")

    net_section = report_data.get("network")
    if net_section:
        lines += ["", "=" * 72, "--- NETWORK PORT SCAN AUDIT ---"]
        lines.append(
            f"Target: {net_section['target']} | "
            f"Range: {net_section['range']} | "
            f"Timeout: {net_section['timeout']}s"
        )

        open_ports = net_section.get("open_ports", [])
        lines.append(f"\n[+] OPEN PORTS ({len(open_ports)}):")
        if open_ports:
            for item in open_ports:
                service = f" ({item['service']})" if item.get("service") else ""
                lines.append(f"  -> {item['port']}{service}")
        else:
            lines.append("  None found.")

        errors = net_section.get("errors", [])
        if errors:
            lines.append(f"\n[!] SCAN ERRORS ({len(errors)}):")
            for item in errors:
                lines.append(f"  -> {item}")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Security Auditor: file integrity monitoring and TCP port scanning."
    )
    parser.add_argument("--dir", required=True, help="Directory to audit.")
    parser.add_argument(
        "--baseline-file",
        default="baseline.json",
        help="Baseline JSON path. Relative paths are resolved inside --dir.",
    )

    action = parser.add_mutually_exclusive_group()
    action.add_argument("--create-baseline", action="store_true")
    action.add_argument("--check", action="store_true")

    parser.add_argument("--scan-ports", action="store_true")
    parser.add_argument("--target", default="127.0.0.1", help="TCP scan target.")
    parser.add_argument("--start-port", type=int, default=1)
    parser.add_argument("--end-port", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--workers", type=int, default=64)
    parser.add_argument("--json-report", help="Optional path for a JSON report.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    root = Path(args.dir).expanduser().resolve()
    if not root.is_dir():
        parser.error(f"Audit directory does not exist or is not a directory: {root}")

    baseline_path = Path(args.baseline_file).expanduser()
    if not baseline_path.is_absolute():
        baseline_path = (root / baseline_path).resolve()
    else:
        baseline_path = baseline_path.resolve()

    monitor = FileMonitor(root, baseline_path=baseline_path)
    report_data: dict[str, Any] = {}

    if args.create_baseline:
        print("\n========== CREATING BASELINE ==========")
        report_data["file_monitor"] = monitor.create_baseline()
    elif args.check:
        print("\n========== RUNNING INTEGRITY CHECK ==========")
        report_data["file_monitor"] = monitor.check_integrity()
    elif not args.scan_ports:
        parser.error("Specify --create-baseline, --check, and/or --scan-ports.")

    if args.scan_ports:
        print("\n========== TCP PORT SCAN ==========")
        try:
            scanner = NetworkScanner(
                target=args.target,
                start_port=args.start_port,
                end_port=args.end_port,
                timeout=args.timeout,
                workers=args.workers,
            )
            report_data["network"] = scanner.scan()
        except ValueError as exc:
            parser.error(str(exc))

    report = generate_text_report(report_data)
    print("\n" + report)

    if args.json_report:
        report_path = Path(args.json_report).expanduser().resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\nJSON report saved to: {report_path}")

    # Non-zero exit is useful for scripts/CI when an integrity change is detected.
    if report_data.get("file_monitor", {}).get("status") == "CHANGED":
        return 2
    if report_data.get("file_monitor", {}).get("status") in {"WARNING", "ERROR"}:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Audit cancelled by user.", file=sys.stderr)
        raise SystemExit(130)
