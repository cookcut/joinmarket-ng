FROM python:3.14-slim

WORKDIR /app

# Install jmcore dependencies first (cached layer)
COPY jmcore/requirements.txt /app/jmcore/requirements.txt
RUN pip install --no-cache-dir -r /app/jmcore/requirements.txt

# Copy jmcore source and install as editable
COPY jmcore /app/jmcore
RUN pip install --no-cache-dir -e /app/jmcore

# Install directory_server dependencies from locked requirements
COPY directory_server/requirements.txt /app/directory_server/requirements.txt
RUN sed -i '/^-e ..\/jmcore/d' /app/directory_server/requirements.txt && \
    pip install --no-cache-dir -r /app/directory_server/requirements.txt

# Copy directory_server source and install as editable
COPY directory_server /app/directory_server
RUN pip install --no-cache-dir -e /app/directory_server

RUN useradd -m -u 1000 jm && \
    chown -R jm:jm /app

USER jm

EXPOSE 5222 8080

ENV NETWORK=mainnet
ENV HOST=0.0.0.0
ENV PORT=5222
ENV LOG_LEVEL=INFO
ENV HEALTH_CHECK_HOST=0.0.0.0
ENV HEALTH_CHECK_PORT=8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["jm-directory-server", "health"]

CMD ["jm-directory-server"]
