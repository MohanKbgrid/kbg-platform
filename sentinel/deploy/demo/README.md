# Sentinel demo in Docker

The same five-minute demo as `python -m sentinel.demo` (a made-up retailer, "Acme Retail", invented data,
a labelled stub in place of a language model), run from the product's own image with one command.

```bash
cd sentinel/deploy/demo
docker compose up --build
```

Then open <http://localhost:8080/console> and paste a token from the log (for example
`demo-dev-ops-head`, the operations head, who can approve the pending step up). Stop with Ctrl-C;
everything is removed with the container.

What it needs: Docker with the compose plugin. It does not need Postgres, an API key or internet access at
run time (the first build downloads the base image and packages).

## Status: not tested

**This compose file has not been run.** It was written in a container with no Docker daemon, and only its YAML
was parsed. Before anyone is pointed at it, run it once on a laptop and check:

1. `docker compose up --build` finishes (the shared `deploy/Dockerfile` installs the PostgreSQL 16 client
   from apt.postgresql.org; behind a TLS-inspecting proxy see the notes at the top of that Dockerfile).
2. The log prints the banner with the tokens, and `docker compose ps` shows the service `healthy`.
3. <http://localhost:8080/console> loads and a token signs in.
4. Ctrl-C stops it within a few seconds.

Known assumptions to confirm: the container's `read_only: true` with a `tmpfs` on `/tmp` is enough for the
demo's SQLite file; the entrypoint override (`python -m sentinel.demo`) replaces the image's `sentinel`
entrypoint.

The port is published on `127.0.0.1` only because the demo tokens are public. Do not expose it on a network.
