# Наш образ = официальный Greenmask (внешняя зависимость, не форк) + Python-клиент
# lookup-service, который Greenmask вызывает локально через custom_transformers (Cmd).
# Cmd/custom_transformers спавнит процесс через exec, поэтому lookup-service должен жить
# в той же файловой системе, что и сам greenmask — сеть используется только до Redis.
FROM greenmask/greenmask:latest

USER root

RUN apt-get update \
    && apt-get install --no-install-recommends -y python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY lookup-service/requirements.txt /opt/lookup-service/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /opt/lookup-service/requirements.txt \
    && pip3 install --break-system-packages --no-cache-dir PyYAML==6.0.*

COPY lookup-service/app/main.py /opt/lookup-service/main.py
RUN chown -R greenmask:greenmask /opt/lookup-service

COPY docker/greenmask/merge_config.py /opt/greenmask-tools/merge_config.py
COPY docker/greenmask/entrypoint.sh /opt/greenmask-tools/entrypoint.sh
RUN chmod +x /opt/greenmask-tools/entrypoint.sh \
    && chown -R greenmask:greenmask /opt/greenmask-tools

RUN mkdir -p /var/lib/greenmask/storage && chown -R greenmask:greenmask /var/lib/greenmask

USER greenmask:greenmask

ENTRYPOINT ["/opt/greenmask-tools/entrypoint.sh"]
