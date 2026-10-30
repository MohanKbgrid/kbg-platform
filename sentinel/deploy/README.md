# Deploying Sentinel (open source, self-hosted)

Two pieces, both built only from open-source components. Claude is the one hosted service, and it is
optional.

| Where | What runs | Folder |
|---|---|---|
| Each customer's server or cloud VM | PostgreSQL 16 + pgvector, Sentinel API, workers, Prometheus, Grafana; DuckDB analytics inside the image | `site/` |
| KBGrid office Mac mini | Ollama (small model + embeddings) behind the Sentinel model gateway | `macmini/` |

```
 Customer site (their server / cloud)                     KBGrid office            Anthropic
 ┌───────────────────────────────────────────┐
 │ db (Postgres 16 + pgvector) ◀── api ◀── events          ┌──────────────────┐
 │        ▲                        │                       │ sentinel gateway │
 │        └──────── worker(s) ─────┼── masked brief ──VPN─▶│   (keys, limits, │──▶ Ollama
 │ prometheus ◀── /metrics         │                       │    usage ledger) │   127.0.0.1
 │ grafana (dashboard)             └── masked brief ─────────────────────────────▶ Claude
 │ sentinel analytics (DuckDB, read-only)                  └──────────────────┘
 └───────────────────────────────────────────┘
```

Data at rest stays at the customer site. Only the masked case summary for a model call leaves it.
Nothing is stored on the Mac mini except a usage ledger (customer, model, tokens), never prompts.

## Customer site

On any Linux machine with Docker:

```bash
git clone https://github.com/MohanKbgrid/kbg-sentinel.git && cd kbg-sentinel/deploy/site
git clone https://github.com/MohanKbgrid/acme-sentinel.git /opt/kbgrid/acme-sentinel   # the overlay
cp .env.example .env                             # passwords, OVERLAY_DIR, models
cp config/tokens.yaml.example config/tokens.yaml
mkdir -p backups && sudo chown 10001 backups     # nightly backups land here
docker compose run --rm api new-token            # once per caller: give out the token, put the hash in tokens.yaml
docker compose up -d --build
```

- API on port 8080 (`/healthz`, `/metrics`, `/v1/...`), Grafana on 3000 with the **Sentinel overview**
  dashboard, Prometheus on 127.0.0.1:9090. Postgres is not published outside the Docker network.
- More throughput: raise `WORKER_REPLICAS` / `WORKER_THREADS`. Workers share the queue safely.
- Models: copy `config/models.yaml.example` to `config/models.yaml`, set `SENTINEL_MODELS=/config/models.yaml`,
  `ANTHROPIC_API_KEY` and `SENTINEL_GATEWAY_KEY` in `.env`. With no models file, model steps go to people.
- Analytics: `docker compose exec api sentinel --pg "$SENTINEL_PG" analytics` (or `analytics models --days 7`,
  `analytics hotspots --fact location`, `analytics --snapshot /data/snap`). The DuckDB extensions are baked
  into the image, so this works without internet.
- Backups: the `maintenance` service backs up nightly into `BACKUP_DIR` (verified, newest `BACKUP_KEEP`
  kept) and archives closed cases older than `RETENTION_DAYS`. Make the directory writable first
  (`mkdir -p backups && sudo chown 10001 backups`) and copy it off the server every night. Restore and the
  restore drill: [OPERATIONS.md](../docs/OPERATIONS.md#backups-restores-and-retention).
- Console sign-in with the company account (OpenID Connect) and WhatsApp / Ask AI edges: see
  [OPERATIONS.md](../docs/OPERATIONS.md).
- Building behind a TLS-inspecting proxy: `docker compose build` with
  `--secret id=ca,src=<ca file>` (see the Dockerfile); the CA is used for the build only.

Verified end to end (ACME overlay, two worker replicas): events in through the API, resolved by
workers, all three metrics targets up in Prometheus, dashboard provisioned in Grafana, analytics
answered from inside the container.

## Mac mini (shared small model)

```bash
git clone https://github.com/MohanKbgrid/kbg-sentinel.git && cd kbg-sentinel/deploy/macmini
bash install.sh                       # installs Ollama + gateway, pulls models; first run creates gateway.yaml
# edit ~/sentinel-gateway/gateway.yaml: one tenant per customer site (token hashes, models, limits)
bash install.sh                       # second run starts the gateway at boot (launchd)
```

- Ollama runs natively (Docker on macOS cannot use the Apple GPU) and listens on 127.0.0.1 only; the
  gateway on port 8090 is the only way in. Reach it from customer sites over a private network
  (Tailscale / WireGuard), never the open internet.
- Customers can only call chat and embeddings, only their allowed models, within their own rate and
  concurrency limits. Pulling, deleting or creating models is impossible through the gateway.
- `GET /usage` (admin token) and `~/sentinel-gateway/usage/usage-YYYY-MM.jsonl` give per-customer token
  counts for billing. `GET /healthz` checks Ollama.
- If the Mac mini is off or busy, sites fall back to Claude automatically (`fallback` in models.yaml)
  and stop trying the Mac mini for the cool-down period.
- Keep it awake and set it to restart after a power failure; a UPS is worth it.
- The repositories are private: give the Mac mini GitHub access once (`gh auth login`) or set
  `SENTINEL_REPO` to a URL with a read token before running `install.sh`.
