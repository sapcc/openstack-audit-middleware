FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt gunicorn

# Copy the middleware source — install as a directory package (no setup.py needed)
COPY auditmiddleware /app/auditmiddleware
COPY etc /app/etc

# Copy the demo app
COPY docker-demo/demo_app.py /app/demo_app.py

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--access-logfile", "-", "demo_app:app"]
