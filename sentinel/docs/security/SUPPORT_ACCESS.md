# Support access to customer sites

KBGrid staff have no standing access to a customer's Sentinel site or data.

- **Asked for, time-boxed, named.** Access is granted by the customer for a stated reason and period, as a
  person in the customer's people configuration (or identity provider) with only the roles needed, and
  removed afterwards.
- **Prefer evidence over access.** Most support works from what the customer can export without giving
  access: `sentinel trace` (read-only, masked), the case explorer's export, the usage export, and logs.
- **Everything is audited.** Support sign-ins and actions appear in the site's audit trail like anyone
  else's and are covered by the audit chain.
- **Hosted tenants.** Operators of the hosted service can reach infrastructure but not tenant data through
  the console without a tenant account; database access is limited to named operators, logged, and used only
  for recovery.
