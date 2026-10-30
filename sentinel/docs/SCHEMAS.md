# JSON Schemas for Sentinel's YAML

Sentinel's configuration is YAML. Each kind has a JSON Schema (draft 2020-12) in `schemas/`, so an editor can
autocomplete keys, show what each field means and underline a mistake before the file is ever published.

| File you edit | Schema |
|---|---|
| `registry.yaml` (roles, fingerprints, exception patterns; also a layer) | `schemas/registry.schema.json` |
| `people.yaml` (role tree, people, assignments, authority) | `schemas/people.schema.json` |
| `models.yaml` (models, routes, fallback, escalation) | `schemas/models.schema.json` |
| `connectors.yaml` (sources, lookups, actions, auth, mcp, edges) | `schemas/connectors.schema.json` |
| `metrics.yaml` (datasets, metrics, monitors) | `schemas/metrics.schema.json` |
| a domain template (`sentinel/templates/*.yaml`) | `schemas/template.schema.json` |
| a connector template (`sentinel/connectors/*.yaml`) | `schemas/connector-template.schema.json` |

## Editor autocomplete

Put this as the first line of the file (YAML language server, used by VS Code's YAML extension, Neovim, JetBrains
and others), with the path relative to the file:

```yaml
# yaml-language-server: $schema=../../../schemas/models.schema.json
models:
  claude:
    provider: anthropic
```

Or associate by file name once, in VS Code `settings.json`:

```json
{ "yaml.schemas": { "schemas/registry.schema.json": "registry*.yaml",
                    "schemas/people.schema.json": "people*.yaml" } }
```

The schemas keep every reference inside the file, so an editor needs no network. Their `$id` values use a
placeholder host, `https://kbg-platform.example/schemas/`, which is not a real address: change `SCHEMA_BASE` in
`scripts/gen_json_schemas.py` to wherever you publish them and regenerate.

## What a schema does and does not check

A schema checks structure and types: a key that does not exist at the top level, a number where text belongs, a
route that is not one of the known routes, a missing `id`. It cannot check what needs the running system or
other files: whether an action exists, whether a role is defined elsewhere, SQL and template expressions,
whether a model name in `routes` is in `models`. Those are still checked by `sentinel validate`, by `sentinel
config check`, and by the console before a version can be published. A file that passes the schema can still be
refused there; a file the schema refuses would have been refused there too.

Inside patterns and sources, fields the loader ignores are not forbidden by the schema either, so a misspelt
optional key is not flagged by the editor (the loaders, too, ignore it).

## Keeping them current

The schemas are generated from the same pydantic models the loaders validate with, so they cannot describe a
field the code lacks:

```
python scripts/gen_json_schemas.py            # rewrite schemas/
python scripts/gen_json_schemas.py --check    # exit 1 if they are stale
```

`tests/test_json_schemas.py` fails when a schema is stale, when a shipped template or example no longer validates,
and checks that deliberately broken files are refused. (`scripts/gen_schema.py` is a different thing: the
PostgreSQL schema.)
