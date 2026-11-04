"""Internal-only scenario service; the dashboard is its authenticated gateway."""
import hmac
import os
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, request
import engine

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2048
API_KEY = os.getenv("DEMO_API_KEY", "")
broker = engine.Broker(os.getenv("DEMO_BROKER_TOKEN", ""))
jobs = OrderedDict()
lock = threading.Lock()
slots = threading.BoundedSemaphore(6)
pool = ThreadPoolExecutor(max_workers=2)


@app.before_request
def authenticate():
    if request.path == "/healthz":
        return None
    supplied = request.headers.get("Authorization", "")
    expected = "Bearer " + API_KEY
    if not API_KEY or not hmac.compare_digest(supplied.encode(), expected.encode()):
        return jsonify(error="Authentication required"), 401


def ready():
    if not API_KEY or not broker.vault.token:
        return False
    try:
        with broker.lock:
            broker.vault.call("GET", "auth/token/lookup-self")
        return True
    except Exception:
        return False


@app.get("/healthz")
def health():
    return ("ok", 200) if ready() else ("Demo broker is unavailable", 503)


@app.get("/v1/capabilities")
def capabilities():
    if not ready():
        return jsonify(error="Demo broker is unavailable; run scripts/run-demo.sh"), 503
    return jsonify(scenarios=sorted(engine.CAPABILITIES))


def public_job(job):
    return dict(job, elapsed=round(time.time() - job["started"], 1)
                if job["state"] in {"queued", "running"} else job.get("elapsed", 0))


@app.get("/v1/jobs")
def recent_jobs():
    with lock:
        return jsonify(jobs=[public_job(j) for j in list(jobs.values())[-15:][::-1]])


@app.get("/v1/jobs/<job_id>")
def job_status(job_id):
    with lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify(error="Run not found; history resets when the demo service restarts"), 404
        return jsonify(public_job(job))


def work(job_id, scenario):
    def progress(text):
        with lock:
            jobs[job_id]["progress"] = text
    with lock:
        jobs[job_id]["state"] = "running"
        jobs[job_id]["progress"] = "Starting the controlled scenario."
    try:
        outcome = engine.run(broker, scenario, job_id, progress)
    except Exception as error:
        details = {"error_type": type(error).__name__}
        if isinstance(error, engine.VaultError):
            details.update(vault_http=error.status, operation=error.operation)
        outcome = engine.result("error", "The scenario could not run. Check service readiness and configuration.",
                                [details])
    finally:
        slots.release()
    with lock:
        job = jobs[job_id]
        job.update(state="done", result=outcome, progress="Finished.",
                   elapsed=round(time.time() - job["started"], 1))


@app.post("/v1/jobs")
def create_job():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"scenario_id"}:
        return jsonify(error="Supply one scenario_id; SQL and commands are not accepted"), 400
    scenario = data["scenario_id"]
    if not isinstance(scenario, str) or scenario not in engine.CAPABILITIES:
        return jsonify(error="Unknown scenario"), 400
    if not ready():
        return jsonify(error="Demo broker is unavailable"), 503
    if not slots.acquire(blocking=False):
        return jsonify(error="Demo queue is full. Wait for a run to finish."), 429
    job_id = uuid.uuid4().hex
    with lock:
        # Retain bounded history without deleting queued/running jobs.
        for old_id in list(jobs):
            if len(jobs) < 100:
                break
            if jobs[old_id]["state"] == "done":
                del jobs[old_id]
        jobs[job_id] = dict(id=job_id, scenario_id=scenario, state="queued",
                            started=time.time(), progress="Waiting for a demo worker.", result=None)
    try:
        pool.submit(work, job_id, scenario)
    except Exception:
        slots.release()
        with lock:
            del jobs[job_id]
        return jsonify(error="Could not queue the demo"), 503
    return jsonify(id=job_id), 202


def renew_broker():
    while True:
        time.sleep(20 * 60)
        try:
            with broker.lock:
                broker.vault.call("POST", "auth/token/renew-self", {})
        except Exception:
            # No privileged fallback and no secret values in logs.
            app.logger.warning("Demo broker renewal failed; rerun scripts/run-demo.sh")


threading.Thread(target=renew_broker, daemon=True).start()
