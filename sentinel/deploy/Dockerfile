# kbg-sentinel runtime image: API, workers, analytics, gateway. Open source throughout.
#   docker build -f deploy/Dockerfile -t kbg-sentinel:<version> .
# Overlays (e.g. acme_sentinel) are mounted at /overlay (see site/compose.yaml) or installed with
#   --build-arg OVERLAY_PIP="<pip spec>"
# Behind a TLS-inspecting corporate proxy, pass its CA for the build only (it is not kept in the image):
#   docker build --secret id=ca,src=/path/to/corporate-ca.crt ...
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SENTINEL_DUCKDB_EXTENSIONS=/opt/duckdb-extensions PYTHONPATH=/overlay

# PostgreSQL 16 client tools (pg_dump / pg_restore of the server's major version) for `sentinel backup`
RUN --mount=type=secret,id=ca \
    if [ -s /run/secrets/ca ]; then cp /run/secrets/ca /usr/local/share/ca-certificates/build-ca.crt; fi; \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && update-ca-certificates \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-16 \
    && apt-get purge -y curl gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/local/share/ca-certificates/build-ca.crt && update-ca-certificates --fresh >/dev/null

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY sentinel ./sentinel
RUN --mount=type=secret,id=ca \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca SSL_CERT_FILE=/run/secrets/ca; fi; \
    pip install ".[postgres,api,analytics,anthropic]"

# DuckDB readers for Postgres/SQLite baked in, so analytics works on sites without internet
RUN --mount=type=secret,id=ca \
    if [ -s /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca CURL_CA_BUNDLE=/run/secrets/ca; fi; \
    python -c "import duckdb; c = duckdb.connect(); c.execute(\"SET extension_directory='/opt/duckdb-extensions'\"); \
c.execute('INSTALL postgres'); c.execute('INSTALL sqlite'); c.execute('LOAD postgres'); c.execute('LOAD sqlite')" \
    && chmod -R a+rX /opt/duckdb-extensions

ARG OVERLAY_PIP=""
RUN --mount=type=secret,id=ca \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    if [ -n "$OVERLAY_PIP" ]; then pip install $OVERLAY_PIP; fi

RUN useradd --system --uid 10001 --create-home sentinel && mkdir -p /overlay /config /data /backups \
    && chown sentinel /data /backups
USER sentinel
ENTRYPOINT ["sentinel"]
CMD ["--help"]
