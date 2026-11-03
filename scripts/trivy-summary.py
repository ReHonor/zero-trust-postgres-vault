#!/usr/bin/env python3
"""Turn a Trivy JSON report into a compact Markdown summary."""
import html
import json
import sys
from collections import defaultdict
from pathlib import Path

def cell(value):
    return html.escape(str(value), quote=False).replace("|", "\\|").replace("\n", " ")

path = Path(sys.argv[1])
if not path.is_file():
    print("No image report was generated. Inspect the build/scanner logs.")
    sys.exit(0)

report = json.loads(path.read_text())
groups = defaultdict(list)
for result in report.get("Results", []):
    for v in result.get("Vulnerabilities") or []:
        groups[(v["VulnerabilityID"], v["Severity"])].append(v)

total = sum(len(rows) for rows in groups.values())
fixable = sum(bool(v.get("FixedVersion"))
              for rows in groups.values() for v in rows)
print("## Image vulnerability summary\n")
print("Image: {}\n".format(cell(report.get("ArtifactName", "unknown"))))
print("Package findings: **{}**; distinct CVEs: **{}**; findings with listed fixes: **{}**.\n".format(
    total, len({key[0] for key in groups}), fixable))
print("| CVE | Severity | Packages and installed versions | Listed fixes | Status |")
print("|---|---|---|---|---|")
for (cve, severity), rows in sorted(groups.items()):
    packages = sorted({
        "{} ({})".format(v["PkgName"], v.get("InstalledVersion", "?"))
        for v in rows
    })
    fixes = sorted({
        "{}: {}".format(v["PkgName"], v["FixedVersion"])
        for v in rows if v.get("FixedVersion")
    })
    statuses = sorted({v.get("Status") or "unspecified" for v in rows})
    values = [cve, severity, "; ".join(packages),
              "; ".join(fixes) or "None listed", ", ".join(statuses)]
    print("| " + " | ".join(cell(v) for v in values) + " |")
