FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY dashboard/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY demo/engine.py demo/server.py demo/test_engine.py ./
COPY app/app.py ./client_lib.py
COPY scripts/monitor.py ./monitor.py
RUN python -m unittest -v test_engine
USER nobody
EXPOSE 8081
ENTRYPOINT ["gunicorn", "--workers", "1", "--threads", "4", "--worker-tmp-dir", "/dev/shm", "--bind", "0.0.0.0:8081", "--access-logfile", "-", "server:app"]
