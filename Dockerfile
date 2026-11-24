# Production Dockerfile for AI Red Team-Driven Blue-Green Validation Engine
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/
COPY src/ /app/src/
COPY examples/ /app/examples/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["agent-sec"]
CMD ["--help"]

