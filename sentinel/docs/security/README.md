# Security overview

For customers' security reviews and questionnaires. Each control names where it lives so it can be checked.
The policies alongside this file describe how KBGrid runs development and support.

| Area | Control | Where |
|---|---|---|
| Hosting | Runs on the customer's own server or a KBGrid-hosted tenant with its own database schema, pool, tokens, secrets scope and licence | `deploy/site`, `sentinel/hosted.py` |
| Authentication | Single sign-on (OpenID Connect) with verified email and account binding; API tokens stored only as SHA-256 hashes; console sessions and tokens can expire and are revoked at once | `sentinel/sso.py`, `sentinel/access.py` |
| Provisioning | SCIM 2.0 from Entra ID / Okta / Google; deactivation takes effect at once | `sentinel/scim.py` |
| Authorisation | Roles with hierarchy and scope; per-action authority with amount limits; rights for configuration, access, kill switch, promotion and reversal; case visibility limited to the roles that work it | `sentinel/rbac.py` |
| Change control | Versioned configuration, maker-checker approval, replay of a draft against recent cases, signed bundles between environments | `sentinel/config.py`, `sentinel/bundles.py` |
| Automation limits | Every exception starts with people; automatic handling only for reversible or safe actions after earned trust; money and customer-facing actions capped at human review; per-hour circuit breaker; kill switch | `sentinel/policy.py`, `sentinel/engine.py` |
| Audit | Every decision, action, configuration change and access event in an append-only log, sealed into a signed hash chain; export and independent verification; optional forwarding to a SIEM | `sentinel/auditchain.py` |
| Personal data | Masking before any model call; DPDP access, correction and erasure tools; erasure redacts without breaking the audit chain; retention by data class | `sentinel/privacy.py`, `sentinel/retention.py`, `docs/privacy/` |
| Model use | Prompts carry masked facts; model output is a proposal checked against the actions and parameters the exception allows; model calls and cost recorded per case | `sentinel/llm.py` |
| Network | Outbound calls only to allow-listed hosts; configuration can read only `SENTINEL_SECRET_*` variables (tenant-scoped in hosted mode); webhooks verified by signature | `sentinel/egress.py`, `sentinel/envsecrets.py`, `sentinel/edges.py` |
| Web | Strict content security policy (no inline script), no-store caching, same-origin forms | `sentinel/api.py` |
| Supply chain | Only open-source runtime dependencies (checked in CI), dependency advisories (pip-audit), image scan (Trivy), secret scan (gitleaks), SBOM per release, signed images with provenance, Dependabot | `.github/workflows/`, `scripts/` |
| Resilience | Checksummed backups that are verified before restore, retries with fencing, dead-letter queue, health and metrics | `sentinel/backup.py`, `docs/OPERATIONS.md` |
| Incidents | Breach runbook with the DPDP notification steps | `docs/privacy/BREACH_RUNBOOK.md` |

Policies: [access control](ACCESS_CONTROL.md), [secure development and change](SECURE_DEVELOPMENT.md),
[vulnerability management](VULNERABILITY_MANAGEMENT.md), [incident response](INCIDENT_RESPONSE.md),
[support access to customer sites](SUPPORT_ACCESS.md). For an outside penetration test: [scope and checklist](PEN_TEST_SCOPE.md).
