"""Command-line entry point.

Usage:
    python -m src.cli scenarios/benign.json
    python -m src.cli scenarios/benign.json --json-only
    python -m src.cli scenarios/benign.json --findings
"""

from __future__ import annotations

import argparse
import json
import sys

from .models import Finding, Scenario, ValidationError
from .rules import assess


def _show(value: object) -> str:
    return "-" if value is None else str(value)


def format_timeline(scenario: Scenario) -> str:
    """Render the chronologically sorted events as a plain-text table."""
    header = ("timestamp", "id", "actor", "source_ip", "method", "path", "status", "marker", "size")
    rows = [header]
    for e in scenario.events:
        path = e.path + (f"?{e.query}" if e.query else "")
        rows.append((
            e.timestamp.isoformat().replace("+00:00", "Z"),
            e.id,
            _show(e.actor_id),
            _show(e.source_ip),
            e.method,
            path,
            _show(e.status),
            _show(e.response_marker),
            _show(e.response_size),
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    return _format_table(rows)


def format_findings(findings: list[Finding]) -> str:
    """Render rule findings as a plain-text table."""
    if not findings:
        return "(none)"
    rows = [("rule", "event_ids", "successful", "summary")]
    for f in findings:
        # json.dumps gives the same true/false/null spelling as the JSON output.
        rows.append((f.rule_id, ",".join(f.event_ids), json.dumps(f.successful), f.summary))
    return _format_table(rows)


def _format_table(rows: list[tuple[str, ...]]) -> str:
    """Left-align rows (first row is the header) into columns."""
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.cli",
        description="Analyze a synthetic API request/response scenario and emit a JSON assessment.",
    )
    parser.add_argument("scenario", help="path to a scenario JSON file")
    parser.add_argument("--json-only", action="store_true", help="print only the JSON assessment")
    parser.add_argument(
        "--findings",
        action="store_true",
        help="add the rule findings to the JSON output under a 'findings' key",
    )
    args = parser.parse_args(argv)

    try:
        scenario = Scenario.load(args.scenario)
        assessment, findings = assess(scenario)
        assessment.validate(scenario.event_ids)
        for finding in findings:
            finding.validate(scenario.event_ids)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output = assessment.to_dict()
    if args.findings:
        output["findings"] = [finding.to_dict() for finding in findings]

    if not args.json_only:
        env = scenario.environment
        print(f"Service: {_show(env.service)}  Deployment: {_show(env.deployment)}")
        print(f"Protected resource: {_show(env.protected_resource)}  Expected access: {_show(env.expected_access)}")
        print()
        print("Timeline")
        print(format_timeline(scenario))
        print()
        print("Findings")
        print(format_findings(findings))
        print()
        print("Assessment")
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
