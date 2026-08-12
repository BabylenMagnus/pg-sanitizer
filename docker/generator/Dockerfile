# LangGraph (external dependency, not forked) orchestrates the offline
# LLM/Faker generation pipeline that pre-populates the mapping store.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY generator/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY generator/generate.py /app/generate.py
COPY generator/test_language_backend.py /app/test_language_backend.py

WORKDIR /app
ENTRYPOINT ["python", "generate.py"]
