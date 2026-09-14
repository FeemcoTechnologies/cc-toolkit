FROM python:3.12-slim

WORKDIR /app

# Build proper edr package structure so "from edr.server.app import create_app" works
RUN mkdir -p /app/edr/server /app/edr/rules

COPY __init__.py ./edr/__init__.py
COPY server/__init__.py ./edr/server/__init__.py
COPY server/__main__.py ./edr/server/__main__.py
COPY server/app.py ./edr/server/app.py
COPY server/models.py ./edr/server/models.py
COPY server/config_api.py ./edr/server/config_api.py
COPY server/ingestion.py ./edr/server/ingestion.py
COPY server/detection.py ./edr/server/detection.py
COPY rules/__init__.py ./edr/rules/__init__.py
COPY rules/schema.py ./edr/rules/schema.py
COPY rules/loader.py ./edr/rules/loader.py
COPY rules/defaults.yaml ./edr/rules/defaults.yaml

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pyyaml zstandard

EXPOSE 8900

CMD ["python", "-m", "uvicorn", "edr.server.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8900"]
