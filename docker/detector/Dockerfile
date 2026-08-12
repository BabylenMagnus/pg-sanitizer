# Presidio (external dependency, not forked) + a thin script that samples
# Postgres and turns findings into a Greenmask config fragment.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY detector/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && python -m spacy download en_core_web_sm

COPY detector/detect.py /app/detect.py

WORKDIR /app
ENTRYPOINT ["python", "detect.py"]
