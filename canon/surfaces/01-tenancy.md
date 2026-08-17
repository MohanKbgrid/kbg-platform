# Surface 1 — Tenancy & company resolution

**Wave 1. Adopt first.** Everything else stamps a tenant, so retrofitting this later means touching
every table you have already written.

## Purpose

A company is a tenant. Companies are **standalone**: different modules, different documents,
different reports, no shared invoice numbering. But they share one database, one deployment, and
one set of masters — because a database per tenant multiplies operational surface without buying
isolation you actually need, and it makes the one thing you genuinely want (inter-company
transactions) impossible.

## The contract

1. **Every transactional table carries `company_id`** from the moment it is created. Not added
   later, not nullable-and-we'll-backfill.
2. **Master/reference data is tenant-scoped too**, unless it is genuinely global. "Genuinely
   global" is a decision someone makes explicitly, not a default. A shared golden identity (one
   customer record across legal entities) is legitimate — but then the *transactions* carry the
   entity stamp, and the master says so in a comment.
3. **Every read endpoint accepts tenant context and scopes by it.** `null` context means the
   unscoped "All" view, which is a deliberate capability for leadership roles — not an accident.
4. **Every write stamps `company_id`** from the resolved tenant, never from the request body. A
   client that can name its own tenant is not a tenancy model.
5. **Module enablement is per company.** A registry lists modules; a matrix says which company has
   which. A module that is off is *absent*, not present-and-erroring.
6. **Connector configuration is per company.** Two companies integrating with the same external
   system use different credentials, endpoints, and codes; the resolver returns the company's row
   over the global one.
7. **Inter-company is a first-class flow, not an exception.** Where one entity manufactures and
   another markets, the transfer between them is a real document with a real posting on both sides
   — not a reporting adjustment.

## Schema shape

```
company            id · code · name · legal_name · is_active
                   ↳ code is the human handle used in headers and URLs; id is the FK everywhere

<any transactional table>
                   company_id  → company.id   (nullable ONLY where a genuinely shared master row
                                               is intended, and the model says why)

company_module     company_id · module_key · is_enabled
company_integration company_id · connector_key · config (jsonb) · is_active
```

**Resolution order** for anything configurable: the company's own row, then the global row, then
refuse. Never a hardcoded fallback.

## Doctrines that bind here

- **D1 deny by default** — an unresolved tenant scopes to nothing, not to everything.
- **D5 config is data** — module and connector enablement are rows.

## The gotcha that will cost you a day

Parameterised tenant filters written as `(:cid is null or col = :cid)` break under async Postgres
drivers when the column is a UUID: the driver cannot infer the parameter's type from a `null`
comparison. Cast explicitly — `(cast(:cid as uuid) is null or col = cast(:cid as uuid))` — and pass
the value as a string. This is not exotic; it will happen on your first scoped list endpoint.

## Gate tests (prose — write these, run them, keep them)

1. **A new table cannot ship without a tenant column.** A test enumerates transactional tables and
   asserts each carries `company_id`; the exception list is explicit and each entry has a reason.
2. **Cross-tenant read is impossible.** Seed two companies with similar rows. Request company A's
   list with A's context; assert B's rows are absent — not filtered in the UI, *absent from the
   response*.
3. **A write cannot choose its own tenant.** Post a create with a `company_id` in the body that
   differs from the resolved context; assert the stored row carries the *resolved* tenant.
4. **The unscoped view is deliberate.** With null context, assert both companies' rows return, and
   assert the endpoint required a role entitled to that view.
5. **A disabled module is absent.** Disable a module for company A; assert its endpoints 404 or
   are omitted from the app registry for A while still working for B.
6. **Connector resolution prefers the company row.** Configure a global connector and a
   company-specific one; assert the company's is returned, and that removing it falls back to
   global rather than to a hardcoded value.
7. **Adding a third company requires no code change.** Insert a company row, enable modules, add
   config. Assert a full transaction round-trip works with zero deploys. *This is the real test of
   the surface* — if it fails, tenancy is hardcoded somewhere.

## Divergence register

| What | Why | Cost |
|---|---|---|
| _(empty — this project follows the canon)_ | | |
