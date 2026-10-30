# Access control policy

Owner: KBGrid engineering lead. Reviewed every six months and after any security incident.

1. **Least privilege.** People get the roles their work needs. Configuration (`__configure__`) and access
   management (`__access__`) rights are held by named people, at least two per site, never shared accounts.
2. **Joiners, movers, leavers.** Where the customer's directory supports SCIM, it is the source of truth and
   access follows group membership the same day. Otherwise the site owner updates the people configuration
   within one working day of a change; leavers are deactivated, not deleted, so the audit stays readable.
3. **Authentication.** Console users sign in through the customer's identity provider with multi-factor
   authentication enforced there. API tokens are per service, stored as hashes, and rotated yearly or at once
   when a person who could see them leaves.
4. **Reviews.** Every quarter the site owner reviews who holds which roles and rights (`sentinel` console,
   People page; the audit log for `meta_denied` and access events) and records the review.
5. **KBGrid staff.** KBGrid has no standing access to customer sites; see [support access](SUPPORT_ACCESS.md).
