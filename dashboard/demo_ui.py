"""Authenticated dashboard pages for the separate, narrowly scoped demo service."""
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Blueprint, abort, redirect, render_template_string, request, session, url_for

demo_bp = Blueprint("demo", __name__, url_prefix="/demo")
with Path(__file__).with_name("demo_catalog.csv").open() as source:
    SCENARIOS = list(csv.DictReader(source, delimiter="|"))
BY_ID = {row["id"]: row for row in SCENARIOS}
API_KEY = os.getenv("DEMO_API_KEY", "")
RUNNER = os.getenv("DEMO_RUNNER_URL", "http://demo-runner:8081").rstrip("/")
LABELS = {"normal": "Normal", "attack": "Attack", "observe": "Observe"}
OUTCOMES = {"allowed": "Allowed as expected", "blocked": "Blocked as expected",
            "observed": "Evidence observed", "insecure": "Baseline weakness demonstrated",
            "unexpected": "Unexpected result", "error": "Could not complete test"}


@demo_bp.record_once
def configure(state):
    key = API_KEY.encode() if API_KEY else secrets.token_bytes(32)
    if not state.app.secret_key:
        state.app.secret_key = hmac.new(key, b"demo-session-key", hashlib.sha256).digest()
    state.app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                            SESSION_COOKIE_NAME="zt_demo_session", SESSION_COOKIE_PATH="/demo")
    if state.app.config.get("MAX_CONTENT_LENGTH") is None:
        state.app.config["MAX_CONTENT_LENGTH"] = 4096


def api(method, path, data=None):
    if not API_KEY:
        raise RuntimeError("The demo service is not configured. Run scripts/run-demo.sh and scripts/run-dashboard.sh.")
    body = None if data is None else json.dumps(data).encode()
    req = Request(RUNNER + "/v1" + path, data=body, method=method,
                  headers={"Authorization": "Bearer " + API_KEY, "Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=5) as response:
            raw = response.read(500_000)
    except HTTPError as error:
        if error.code == 429:
            raise RuntimeError("The demo queue is full. Wait for a run to finish.") from None
        if error.code == 404:
            raise RuntimeError("That run is no longer in history. History resets after a demo-service restart.") from None
        raise RuntimeError("The demo service is not ready (HTTP %s)." % error.code) from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("The demo service could not be reached. Check scripts/run-demo.sh.") from None
    return json.loads(raw)


def csrf():
    if "demo_csrf" not in session:
        session["demo_csrf"] = secrets.token_urlsafe(32)
    return session["demo_csrf"]


STYLE = """
body{margin:0;background:#0b1220;color:#e5edf8;font:15px/1.5 system-ui,sans-serif}
main{max-width:1240px;margin:auto;padding:28px}a{color:#9ec5ff;text-decoration:none}
h1{font-size:32px;margin:20px 0 4px}h2{font-size:18px;margin:10px 0}p{color:#aebdd1}
nav,.actions{display:flex;gap:9px;flex-wrap:wrap;margin:16px 0}
nav a,.back{padding:8px 13px;background:#1b2a42;border:1px solid #30415c;border-radius:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(275px,1fr));gap:16px}
article,.panel{background:#132038;border:1px solid #30415c;border-radius:12px;padding:18px}
article{display:flex;flex-direction:column}article form{margin-top:auto;padding-top:14px}
.tag{display:inline-block;font-size:12px;border-radius:5px;padding:4px 7px;background:#253851}
.attack{color:#fda4af}.normal{color:#86efac}.observe{color:#c4b5fd}.muted{color:#aebdd1}
.notice{background:#263754;padding:12px 16px;border-radius:8px;margin:16px 0}
.error{background:#592737;color:#ffe4e6}.good{color:#86efac}.bad{color:#fda4af}
button{padding:10px 17px;border:0;border-radius:7px;background:#3b82f6;color:white;font:inherit;cursor:pointer}
button:disabled{background:#334155;color:#94a3b8;cursor:not-allowed}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:9px;border-bottom:1px solid #30415c}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#091322;border-radius:8px;padding:15px;color:#d7e5f8}
.spinner{display:inline-block;width:10px;height:10px;border-radius:50%;background:#60a5fa;margin-right:8px}
@media(max-width:600px){main{padding:18px}h1{font-size:26px}.panel{overflow-x:auto}}
"""

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zero-trust Demo Lab</title><style>{{ style }}</style></head><body><main>
<a class="back" href="/">Back to dashboard</a>
<h1>Zero-trust Demo Lab</h1><p>Run normal activity and controlled attack attempts. See the actual result and the control involved.</p>
{% if error %}<div class="notice error">{{ error }}</div>{% endif %}
<div class="notice">Fresh identities are used for protected-database tests. Table writes are rolled back.
Audit events and sequence counters can still change. Baseline tests use a separate database containing fake data.</div>
<nav><a href="/demo/">All scenarios</a><a href="/demo/?kind=normal">Normal activity</a>
<a href="/demo/?kind=attack">Attack attempts</a><a href="/demo/?kind=observe">Audit and monitoring</a></nav>
<nav>{% for group in groups %}<a href="{{ url_for('demo.catalog',group=group) }}">{{ group }}</a>{% endfor %}</nav>
<p>{{ scenarios|length }} shown / {{ total }} scenarios. {{ available|length }} available.</p>
<div class="grid">{% for s in scenarios %}<article>
<div><span class="tag">{{ s.group }}</span> <span class="tag {{ s.kind }}">{{ labels[s.kind] }}</span></div>
<h2>{{ s.title }}</h2><p><strong>Expected:</strong> {{ s.expected }}</p>
{% if s.id in ['expiry','baseline_reuse'] %}<p class="muted">Includes a real expiry/reuse wait; progress appears on the next page.</p>{% endif %}
<form method="post" action="{{ url_for('demo.launch',scenario_id=s.id) }}">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button type="submit" {% if s.id not in available %}disabled{% endif %}>Run scenario</button></form>
</article>{% endfor %}</div>
<section class="panel" style="margin-top:24px"><h2>Recent runs</h2><table>
<tr><th>Scenario</th><th>Status</th><th>Result</th></tr>
{% for job in jobs %}<tr><td><a href="{{ url_for('demo.status',job_id=job.id) }}">{{ by_id.get(job.scenario_id,{}).get('title',job.scenario_id) }}</a></td>
<td>{{ job.state }}</td><td>{{ outcomes.get(job.result.outcome,'') if job.result else '' }}</td></tr>
{% else %}<tr><td colspan="3">No runs yet.</td></tr>{% endfor %}</table></section>
</main></body></html>"""

RESULT_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{% if job and job.state != 'done' %}<meta http-equiv="refresh" content="2">{% endif %}
<title>Demo result</title><style>{{ style }}</style></head><body><main>
<a class="back" href="/demo/">Back to Demo Lab</a><h1>{{ scenario.title if scenario else 'Demo result' }}</h1>
{% if error %}<div class="notice error">{{ error }}</div>{% endif %}
{% if job %}<section class="panel">
<p><strong>Expected:</strong> {{ scenario.expected }}</p>
<p><strong>Elapsed:</strong> {{ job.elapsed }} seconds</p>
{% if job.state != 'done' %}<h2><span class="spinner"></span>{{ job.state|capitalize }}</h2><p>{{ job.progress }}</p>
<p>This page refreshes while the test runs. Leaving the page does not cancel the test.</p>
{% else %}<h2 class="{{ 'bad' if job.result.outcome in ['unexpected','error'] else 'good' }}">{{ outcomes[job.result.outcome] }}</h2>
<p>{{ job.result.summary }}</p>
{% if job.result.user %}<p><strong>Temporary identity:</strong> {{ job.result.user }}</p>{% endif %}
<h2>Evidence</h2><pre>{{ job.result.evidence|tojson(indent=2) }}</pre>
<form method="post" action="{{ url_for('demo.launch',scenario_id=job.scenario_id) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<button type="submit">Run again</button></form>{% endif %}
</section>{% endif %}</main></body></html>"""


@demo_bp.get("/")
def catalog():
    rows = SCENARIOS
    for key in ("kind", "group"):
        value = request.args.get(key)
        if value:
            rows = [s for s in rows if s[key] == value]
    available, jobs, error = [], [], None
    try:
        available = api("GET", "/capabilities")["scenarios"]
        jobs = api("GET", "/jobs")["jobs"]
    except Exception as exc:
        error = str(exc) if isinstance(exc, RuntimeError) else "The demo service returned an invalid response."
    return render_template_string(PAGE, scenarios=rows, total=len(SCENARIOS), available=available,
                                  groups=sorted({s["group"] for s in SCENARIOS}), labels=LABELS,
                                  jobs=jobs, by_id=BY_ID, outcomes=OUTCOMES, error=error, csrf=csrf(), style=STYLE)


@demo_bp.post("/<scenario_id>/run")
def launch(scenario_id):
    if scenario_id not in BY_ID:
        abort(404)
    origin = request.headers.get("Origin")
    if origin and origin != request.host_url.rstrip("/"):
        abort(403, f"Address mismatch: browser={origin!r}; server={request.host_url.rstrip(chr(47))!r}")
    supplied, expected = request.form.get("csrf", ""), session.get("demo_csrf", "")
    if not expected or not hmac.compare_digest(supplied.encode(), expected.encode()):
        abort(403, "Refresh the Demo Lab page before running a scenario")
    try:
        queued = api("POST", "/jobs", {"scenario_id": scenario_id})
    except RuntimeError as exc:
        return render_template_string(RESULT_PAGE, job=None, scenario=BY_ID[scenario_id],
                                      error=str(exc), style=STYLE), 503
    return redirect(url_for("demo.status", job_id=queued["id"]), code=303)


@demo_bp.get("/jobs/<job_id>")
def status(job_id):
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        abort(404)
    try:
        job = api("GET", "/jobs/" + job_id)
        scenario = BY_ID[job["scenario_id"]]
        return render_template_string(RESULT_PAGE, job=job, scenario=scenario, error=None,
                                      outcomes=OUTCOMES, csrf=csrf(), style=STYLE)
    except RuntimeError as exc:
        return render_template_string(RESULT_PAGE, job=None, scenario=None, error=str(exc), style=STYLE), 503
