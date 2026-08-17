# Surface 2 — Config (external services, secrets, and business thresholds)

**Wave 1.** RBAC and Integration both read it, so it lands before them.

## Purpose

Two things live here and they are often wrongly separated: **credentials for external services**
(an LLM provider, a messaging gateway, an SMTP relay, a payment rail) and **business thresholds**
(how many days, what percentage, what distance). They belong on one surface because they share the
same three properties: per-tenant, changed without a deploy, and audited.

The alternative — credentials in environment variables and thresholds in constants — fails the same
way twice. A new company means a redeploy, and nobody can answer "who changed that, and when".

## The contract

### Credentials
1. **Secret fields are encrypted at rest** and are **write-only** through the API. The read path is
   structurally unable to decrypt: `list` and `get` return masked values, and the decrypting
   resolver is a separate in-process function that no route calls directly.
2. **A registry declares what each service needs**, and which of its fields are secret. The registry
   is *code*, not a database constraint — a provider list grows whenever the business buys
   something, and putting it in a `CHECK` makes "we signed up for X" a migration.
3. **Writes are versioned**: validate → seal → supersede → audit. The previous credential stays in
   the record as superseded, so "when did this key change" is answerable.
4. **Resolution is per company, falling back to global, then refusing.**

### Business thresholds
5. **Any number a business owner might plausibly want to change is a row**, not a constant. The test
   is simple: if someone could ask "can we make that 300 instead of 200", it is data.
6. **A missing policy row REFUSES.** It must never mean "no rule fired" — a control that fails open
   is worse than an absent one, because it looks present.
7. **Thresholds ship with the values the specification stated**, seeded by the migration, with a
   note recording that they are starting values to be tuned against live data.

### Communications routing
8. **Route by PURPOSE, not by provider.** The application says "notify this person that their
   approval is pending"; the config says purpose → channel → provider. Changing from one messaging
   provider to another is then a config edit, and a domain that needs a different channel (a farmer
   on SMS, a distributor on WhatsApp) is a policy row rather than a branch in the code.

## Schema shape

```
external_service_config   company_id · service_key · config (jsonb, secrets sealed)
                          · version · supersedes_id · superseded_at/by · created_by · created_at

comm_routing_policy       company_id · purpose · channel · provider_key · is_active
                          ↳ purpose is the application's vocabulary; provider is the config's

<domain>_policy           company_id · <threshold columns> · note · updated_at
                          ↳ one per domain that has thresholds; NOT one giant key/value table,
                            because a numeric column can carry a CHECK and a key/value string
                            cannot
```

## Doctrines that bind here

- **D5 config is data** — this surface *is* that doctrine.
- **D1 deny by default** — unresolved config refuses.
- **D2 append-only** — credential changes supersede.

## Gate tests

1. **A secret cannot be read back.** Store a credential; call every read endpoint; assert the secret
   value appears nowhere in any response, and that the returned mask is not reversible.
2. **The resolver decrypts and the API does not.** Assert the in-process resolver returns the real
   value, and that no route handler calls it on a path that serializes to the client.
3. **A rotation supersedes rather than overwrites.** Change a credential twice; assert three
   versions exist, exactly one active, and the audit names who changed each.
4. **Company config beats global.** Configure both; assert the company's wins; delete it; assert
   fallback to global; delete that; assert a **refusal**, not a default.
5. **A missing policy row refuses.** Delete the policy for a company and assert the dependent
   feature raises a named error — *not* that it silently proceeds with a built-in number.
6. **Changing config changes behaviour, with no deploy.** The important one. Change a threshold row;
   re-run the same input; assert the output changed, and that the underlying measurement did not.
   (E.g. move a distance threshold and assert the flag flips while the measured distance is
   identical.) A gate that only asserts the happy path passes equally well against a hardcoded
   constant.
7. **Purpose routing is provider-agnostic.** Point one purpose at a different provider; assert the
   calling code was not touched and the message routed differently.

## Divergence register

| What | Why | Cost |
|---|---|---|
| `comm_routing_policy` exists but holds **0 rows** — purpose→channel routing is modelled, not populated | No notification traffic in production yet. | Purpose-based routing is unproven. The first real send will exercise a code path nothing has run. |
| _Otherwise conforms_ — secrets encrypted at rest, write-only through the API, versioned with supersede + audit, company-over-global resolution, thresholds as data with a control-controls gate. | | |
