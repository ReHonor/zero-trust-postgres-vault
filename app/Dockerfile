FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir hvac==2.4.0 psycopg2-binary==2.9.13
WORKDIR /app
COPY app.py /app/app.py
USER nobody
ENTRYPOINT ["python", "/app/app.py"]
