# Penetration test: scope and checklist

For the outside firm that tests a Sentinel site before a customer goes live, and once a year after. It says
what is in scope, how to set up the test environment, what to try against each surface, and what KBGrid needs
back. Security contact: mohanp@kbgrid.com (see [SECURITY.md](../../SECURITY.md)).

## Rules of engagement

- Test a **staging site** set up for the purpose (below), never a customer's live site, unless the customer
  and KBGrid agree to it in writing with dates and source addresses.
- Grey box: the firm gets the source code at the tag under test, this document, accounts for each role and
  the API tokens listed below. Signed release images and their SBOM are at the release tag.
- Out of scope: denial of service by volume, social engineering of KBGrid or customer staff, the customer's
  own systems (Shopify, the WMS and so on) and the third-party services Sentinel calls (Anthropic, Meta
  WhatsApp, Gupshup, Interakt, Slack, Microsoft Teams). Point connectors at the firm's own mock
  servers instead.
- Stop and tell KBGrid at once on finding anything that exposes another tenant's data, a stored key, remote
  code execution or a way past the review step for money or customer-facing actions.

## Test environment

| Item | Setting |
|---|---|
| Version | The release tag under test (`sentinel --version`); image verified with `cosign verify` as in SECURITY.md |
| Store | PostgreSQL; one site in single-tenant mode and one in hosted mode with at least two tenants |
| Console | SSO through a test OpenID Connect provider, plus local accounts for each role |
| Keys | `SENTINEL_MASTER_KEY` set, several connector keys entered on the Keys page |
| Edges | WhatsApp (Meta), Gupshup, Interakt, Slack, Teams and an A2UI edge pointed at mock servers |
| Data | The demo overlay (`python -m sentinel.demo`) with cases, reviews and audit history |
| Accounts | One person per role: viewer, reviewer, approver with an amount limit, configurer (`__configure__`), access admin, a person scoped to one system; an expired and a revoked token |

## Surfaces and what to try

### 1. Console and its API (`/console`, `/console/api/*`, `/console/m`)

- [ ] Authentication: session fixation, cookie flags (Secure, HttpOnly, SameSite), logout and expiry, revoked
  sessions, brute force on local login, SSO callback (state, nonce, issuer, audience, unverified email,
  account binding to an existing person).
- [ ] Authorisation on every endpoint, for every role: reading cases outside the person's scope, deciding a
  review above the approver's amount limit, publishing configuration without `__configure__`, approving one's
  own configuration (maker-checker), reversing, promoting, the kill switch, people and access changes.
- [ ] Insecure direct object references: incident, review, configuration version, pattern and key ids of
  another scope or tenant.
- [ ] Cross-site request forgery on every state-changing call; cross-site scripting through case facts,
  people's names, configuration text, model output and translated card text (the console must render it as
  text); the content security policy (no inline script) and caching headers.
- [ ] Keys page: a stored key's value must never come back in any response, log, audit entry, export, backup
  listing or error; names outside `SENTINEL_SECRET_` / `SENTINEL_EDGE_` (and outside the tenant's prefix in
  hosted mode) are refused; "Test login" must not reveal the key or reach a host outside the allow-list.

### 2. Machine API (`/v1/*`, `/healthz`, `/metrics`, `/usage`)

- [ ] Token handling: missing, malformed, expired, revoked and other-tenant tokens; token scopes.
- [ ] Event ingestion (`/v1/events`, `/v1/hooks/{source}`, `/v1/sources/{source}`): signature checks per
  source (HMAC, base64 HMAC, token mode), replayed and re-timestamped requests, oversized and deeply nested
  bodies, XML with DOCTYPE or entity declarations (must be refused), injection through fields that reach
  templates (`{{...}}`) or SQL sources.
- [ ] Decisions (`/v1/reviews/*`, `/v1/incidents/*/reverse`, `/v1/patterns/*`): the same authorisation tests
  as the console, and bulk decisions mixing allowed and forbidden items.
- [ ] `/metrics` and `/healthz` disclose nothing beyond counts and status.

### 3. Inbound webhooks from chat and payment providers

- [ ] WhatsApp (`/v1/whatsapp/{edge}`): the verify handshake, `X-Hub-Signature-256`, replies from numbers no
  person has (must be refused and audited), a reply for a review the sender may not decide.
- [ ] Gupshup and Interakt (`/v1/wa/{edge}`): the shared token and `Interakt-Signature`, forged
  `sentinel:<review>:<decision>` strings placed anywhere in the payload.
- [ ] Slack (`/v1/slack/{edge}`), Teams and A2UI (`/v1/edges/{edge}/a2ui`, `/answers`): signature and
  timestamp windows, replays, a userAction naming a review of another person or tenant.

### 4. SCIM (`/scim/v2`)

- [ ] Bearer token, filter injection, creating or elevating a person into a role the directory does not
  grant, deactivation taking effect on open sessions and tokens at once.

### 5. Outbound calls and configuration

- [ ] Server-side request forgery through configuration: connector URLs, lookups, `auth:` logins, edge URLs
  and redirects to private, link-local, metadata (169.254.169.254) and loopback addresses, DNS rebinding;
  only allow-listed hosts may be reached.
- [ ] Configuration that reads server secrets: `{{env.X}}` or `*_env` naming anything other than
  `SENTINEL_SECRET_*` / `SENTINEL_EDGE_*` (for example `ANTHROPIC_API_KEY`, `SENTINEL_MASTER_KEY`,
  `DATABASE_URL`) must be refused at save and at run time.
- [ ] Template injection: values from events and model output must not be evaluated as templates or code.
- [ ] Signed bundles and the pack catalogue: tampered, re-signed with another key, or with paths outside the
  configuration directory.

### 6. Model use

- [ ] Prompt injection through case facts (order notes, customer messages, ticket text) trying to make the
  model propose an action the exception does not allow, change parameters beyond limits, skip review or
  leak other cases. The proposal check must refuse it; record what the model said.
- [ ] Personal data in prompts: phone numbers, emails, addresses and names must be masked before the call.

### 7. Hosted mode (multi-tenant)

- [ ] Every test above across tenants: data, keys, configuration, audit, usage exports, cache keys (login
  tokens, translations) and edges of one tenant must be unreachable from another.
- [ ] The tenant's database schema and pool: SQL sources and lookups cannot read another schema.

### 8. Data at rest and operations

- [ ] Keys in the database are AES-256-GCM ciphertext bound to their name and tenant; a row copied to another
  name or tenant does not decrypt; backups hold no plaintext keys; the master key is not in the database.
- [ ] Audit chain: altering, deleting or reordering an entry is detected by `sentinel audit verify`; erasure
  of personal data keeps the chain verifiable.
- [ ] Backup and restore: a tampered backup is refused before restore.
- [ ] The container image: runs as a non-root user, no secrets in layers, no unexpected listening ports.

### 9. Supply chain

- [ ] The SBOM matches the image; `pip-audit` and Trivy results at the tag; the image signature and
  provenance verify.

## What KBGrid needs back

- A report with each finding's severity (CVSS 3.1 or 4.0), the affected surface and endpoint, steps to
  reproduce, evidence, and a suggested fix; a short summary for the customer.
- Findings of high or critical severity told to mohanp@kbgrid.com on the day they are found.
- A retest of fixed findings; KBGrid fixes critical findings within 7 days and high within 30
  ([vulnerability management](VULNERABILITY_MANAGEMENT.md)) and records them in the release notes.
- A letter of attestation naming the version tested and the dates, for customers' security reviews.
