"""JSON, Markdown, and HTML reporting."""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, select_autoescape

from devsecops_scanner.models import Finding, Severity


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DevSecOps Scanner Executive Report</title>
<style>
:root{color-scheme:light;--ink:#14213d;--muted:#5b6474;--line:#dce2ea;--surface:#f4f7fb}
body{font:15px/1.5 system-ui,sans-serif;color:var(--ink);background:var(--surface);margin:0}
main{max-width:1100px;margin:32px auto;padding:0 20px}.header,.panel{background:white;border:1px solid var(--line);
border-radius:12px;padding:22px;margin-bottom:18px}.header h1{margin:0 0 6px}.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{padding:15px;border:1px solid var(--line);border-radius:9px}.card strong{font-size:26px;display:block}
.critical{color:#a20e24}.high{color:#b54708}.medium{color:#946200}.low{color:#287342}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;color:var(--muted)}code{word-break:break-word}
select,input{font:inherit;padding:8px;border:1px solid var(--line);border-radius:6px;margin:0 8px 10px 0}
@media(max-width:700px){table,tbody,tr,td{display:block}thead{display:none}td{border-bottom:0;padding:5px 10px}}
</style>
</head>
<body><main>
<section class="header"><h1>Security Scan</h1><div class="muted">Generated {{ generated }} · Scope: {{ scope }}</div>
<p>Risk score <strong>{{ score }}/100</strong> · {{ findings|length }} finding(s)</p></section>
<section class="panel"><h2>Executive summary</h2><div class="cards">
{% for severity in severities %}<div class="card {{ severity|lower }}"><span>{{ severity }}</span>
<strong>{{ counts[severity] }}</strong></div>{% endfor %}
</div></section>
<section class="panel"><h2>Findings</h2>
<label for="severity">Severity</label><select id="severity"><option value="">All severities</option>
{% for severity in severities %}<option>{{ severity }}</option>{% endfor %}</select>
<input id="search" type="search" placeholder="Filter by file, rule, or title" aria-label="Filter findings">
<div style="overflow-x:auto"><table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Recommendation</th></tr></thead>
<tbody id="findings">{% for item in findings %}<tr data-severity="{{ item.severity.name.title() }}"
data-search="{{ item.file_path }} {{ item.rule_id }} {{ item.title }}">
<td class="{{ item.severity.name|lower }}">{{ item.severity.name.title() }}</td>
<td><strong>{{ item.title }}</strong><br>{{ item.message }}<br><small>{{ item.rule_id }}{% if item.cve %} · {{ item.cve }}{% endif %}</small></td>
<td><code>{{ item.file_path }}:{{ item.line }}</code></td><td>{{ item.recommendation }}</td></tr>
{% else %}<tr><td colspan="4">No findings. Good work!</td></tr>{% endfor %}</tbody></table></div>
</section></main>
<script>
const severity=document.querySelector('#severity'),search=document.querySelector('#search');
function filterRows(){const query=search.value.toLowerCase();for(const row of document.querySelectorAll('#findings tr[data-severity]')){
row.hidden=(severity.value&&row.dataset.severity!==severity.value)||!row.dataset.search.toLowerCase().includes(query)}}
severity.addEventListener('change',filterRows);search.addEventListener('input',filterRows);
</script></body></html>"""

SEVERITIES = ("Critical", "High", "Medium", "Low")
WEIGHTS = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 1}


def _summary(findings: list[Finding]) -> tuple[Counter[str], int]:
    counts = Counter(finding.severity.name.title() for finding in findings)
    score = min(100, sum(WEIGHTS[finding.severity] for finding in findings))
    return counts, score


def render_json(findings: list[Finding], scope: str) -> str:
    counts, score = _summary(findings)
    return json.dumps({
        "tool": "devsecops-scanner",
        "scope": scope,
        "summary": {"total": len(findings), "risk_score": score,
                    "by_severity": {severity: counts[severity] for severity in SEVERITIES}},
        "findings": [finding.to_dict() for finding in findings],
    }, indent=2) + "\n"


def render_markdown(findings: list[Finding], scope: str) -> str:
    counts, score = _summary(findings)
    lines = [
        "# DevSecOps Scanner Report", "", f"- **Scope:** `{scope}`",
        f"- **Findings:** {len(findings)}", f"- **Risk score:** {score}/100", "",
        "## Summary", "", "| Severity | Count |", "|---|---:|",
    ]
    lines.extend(f"| {severity} | {counts[severity]} |" for severity in SEVERITIES)
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No findings.")
    for finding in findings:
        lines.extend([
            f"### {finding.severity.name.title()}: {finding.title}",
            f"- **Rule:** `{finding.rule_id}`",
            f"- **Location:** `{finding.file_path}:{finding.line}`",
            f"- **Category:** {finding.category}",
            f"- **Details:** {finding.message}",
            f"- **Recommendation:** {finding.recommendation}",
        ])
        if finding.cve:
            lines.append(f"- **CVE:** {finding.cve}")
        lines.append("")
    return "\n".join(lines)


def render_html(findings: list[Finding], scope: str) -> str:
    counts, score = _summary(findings)
    environment = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    template = environment.from_string(HTML_TEMPLATE)
    return template.render(
        findings=findings, scope=scope, counts=counts, score=score,
        severities=SEVERITIES, generated=datetime.now().astimezone().isoformat(timespec="seconds"),
    )


def write_report(output: Path, findings: list[Finding], scope: str) -> None:
    """Render based on the destination extension and write a UTF-8 report."""
    extension = output.suffix.lower()
    renderers = {
        ".json": render_json,
        ".md": render_markdown,
        ".markdown": render_markdown,
        ".html": render_html,
        ".htm": render_html,
    }
    try:
        renderer = renderers[extension]
    except KeyError as exc:
        raise ValueError("Output extension must be .json, .md, or .html.") from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(renderer(findings, scope), encoding="utf-8")
