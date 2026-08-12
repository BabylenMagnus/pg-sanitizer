# Runs both the FastAPI app and the Celery worker (command differs per
# service in docker-compose.yml). The worker needs a real `docker` CLI +
# compose plugin plus the host's Docker socket to shell out to the sibling
# detector/generator/greenmask services — see api/README.md "Docker deploy"
# for why this only works when the bind-mounted source path matches the
# host path exactly (classic sibling-container caveat, Linux prod only).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y curl ca-certificates gnupg libpq-dev gcc \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install --no-install-recommends -y docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api/app /app/app

WORKDIR /app
