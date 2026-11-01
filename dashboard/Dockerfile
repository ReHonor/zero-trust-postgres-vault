FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER nobody
EXPOSE 8080
# One worker: the single-use secret_id allows exactly one Vault login, so no multiple processes.
ENTRYPOINT ["gunicorn", "--workers", "1", "--threads", "4", "--worker-tmp-dir", "/dev/shm", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "app:app"]
