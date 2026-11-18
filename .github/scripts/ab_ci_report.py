#!/usr/bin/env python3
"""The durations of the CI A/B experiment (.github/workflows/ab-ci.yml) as a table.

Launch (one run per variant, from the branch that carries the workflow):

    gh workflow run ab-ci.yml --ref ci/ab-experiment -f variant=baseline -f reps=5 -f linux=true
    gh workflow run ab-ci.yml --ref ci/ab-experiment -f variant=rust-lld
    gh workflow run ab-ci.yml --ref ci/ab-experiment -f variant=dev-drive
    gh workflow run ab-ci.yml --ref ci/ab-experiment -f variant=win2022-d
    gh workflow run ab-ci.yml --ref ci/ab-experiment -f variant=deps-nodebug -f linux=true

Report (needs `gh`, signed in):

    python .github/scripts/ab_ci_report.py [--repo OWNER/NAME] [--branch BRANCH] [RUN_ID ...]

Without run ids it reads every completed manual run of ab-ci.yml on the branch. For each kind,
mode and variant: the successful jobs `n`, the minutes of the `Measured build` step (median,
min, max), its change against the median of `baseline` for the same kind and mode, the median
job time and, for warm runs, of the `Restore the warm state` step. Then the runner minutes of
every run (all its jobs) and the commits measured: variants are comparable on one commit only.
"""

import argparse
import json
import re
import statistics
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from urllib.parse import quote

WORKFLOW = "ab-ci.yml"
JOB = re.compile(r"^ab (?P<variant>\S+) (?P<mode>cold|warm) (?P<kind>\S+) #(?P<rep>\d+)$")
MEASURED = "Measured build"
RESTORE = "Restore the warm state"
BASELINE = "baseline"


def gh(path):
    out = subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def pages(path, key):
    sep = "&" if "?" in path else "?"
    page = 1
    while True:
        items = gh(f"{path}{sep}per_page=100&page={page}")[key]
        yield from items
        if len(items) < 100:
            return
        page += 1


def minutes(item):
    start, end = item.get("started_at"), item.get("completed_at")
    if not start or not end:
        return None
    parse = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
    return (parse(end) - parse(start)).total_seconds() / 60


def step(job, name):
    for s in job.get("steps") or []:
        if s["name"] == name and s.get("conclusion") == "success":
            return minutes(s)
    return None


def fmt(value):
    return "-" if value is None else f"{value:.1f}"


def table(header, rows):
    widths = [max(len(str(r[i])) for r in [header, *rows]) for i in range(len(header))]
    for r in [header, ["-" * w for w in widths], *rows]:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip())


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo", default="arynyklas/OpenNCALayer")
    parser.add_argument("--branch", default="ci/ab-experiment")
    parser.add_argument("runs", nargs="*", type=int, help="run ids (default: all on the branch)")
    args = parser.parse_args()
    repo = args.repo

    if args.runs:
        runs = [gh(f"repos/{repo}/actions/runs/{r}") for r in args.runs]
    else:
        runs = list(
            pages(
                f"repos/{repo}/actions/workflows/{WORKFLOW}/runs"
                f"?branch={quote(args.branch, safe='')}&event=workflow_dispatch&status=completed",
                "workflow_runs",
            )
        )
    if not runs:
        sys.exit(f"no completed manual runs of {WORKFLOW} on {args.branch}")

    builds = defaultdict(list)  # (kind, mode, variant) -> [build minutes]
    jobs_min = defaultdict(list)
    restores = defaultdict(list)
    failed = defaultdict(int)
    per_run = []
    for run in runs:
        run_minutes, variants = 0.0, set()
        for job in pages(f"repos/{repo}/actions/runs/{run['id']}/jobs", "jobs"):
            run_minutes += minutes(job) or 0.0
            m = JOB.match(job["name"])
            if not m:
                continue
            key = (m["kind"], m["mode"], m["variant"])
            variants.add(m["variant"])
            build = step(job, MEASURED)
            if job["conclusion"] != "success" or build is None:
                failed[key] += 1
                continue
            builds[key].append(build)
            jobs_min[key].append(minutes(job))
            restore = step(job, RESTORE)
            if restore is not None:
                restores[key].append(restore)
        per_run.append((run["id"], ",".join(sorted(variants)) or "?", run["head_sha"][:8], run_minutes))

    rows = []
    for kind, mode, variant in sorted(set(builds) | set(failed), key=lambda k: (k[0], k[1], k[2] != BASELINE, k[2])):
        key = (kind, mode, variant)
        b = builds.get(key, [])
        median = statistics.median(b) if b else None
        base = builds.get((kind, mode, BASELINE))
        delta = "-"
        if median is not None and base and variant != BASELINE:
            base_median = statistics.median(base)
            delta = f"{(median - base_median) / base_median * 100:+.0f}%"
        rows.append([
            kind, mode, variant, len(b),
            fmt(median), fmt(min(b) if b else None), fmt(max(b) if b else None), delta,
            fmt(statistics.median(jobs_min[key]) if jobs_min.get(key) else None),
            fmt(statistics.median(restores[key]) if restores.get(key) else None),
            failed.get(key, 0),
        ])
    print("Measured build, minutes")
    table(["kind", "mode", "variant", "n", "median", "min", "max", "Δ base", "job", "restore", "failed"], rows)

    print("\nRuns")
    table(
        ["run", "variant", "commit", "runner min"],
        [[r, v, sha, f"{m:.0f}"] for r, v, sha, m in per_run],
    )
    print(f"total runner minutes: {sum(m for *_, m in per_run):.0f}")
    if len({sha for _, _, sha, _ in per_run}) > 1:
        print("warning: the runs measured more than one commit", file=sys.stderr)


if __name__ == "__main__":
    main()
