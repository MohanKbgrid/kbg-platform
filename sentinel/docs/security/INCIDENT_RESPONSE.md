# Incident response

1. **Detect.** Health and metrics alerts, audit-chain verification failures (`sentinel audit verify`),
   unusual `meta_denied` or access events, reports from customers or researchers.
2. **Contain.** Use the kill switch to stop automatic handling for the affected exceptions or the whole site;
   revoke tokens and sessions; block egress hosts; take the console off the network if needed. Every case
   then waits for a person and nothing is lost.
3. **Assess.** Export and verify the audit chain to fix the timeline and prove what was and was not changed.
   Decide whether personal data was affected.
4. **Notify.** For personal data, follow [the breach runbook](../privacy/BREACH_RUNBOOK.md) (DPDP Board and
   affected people). Tell the customer's named contact within 24 hours of confirming an incident.
5. **Recover and learn.** Restore from verified backups if needed, rotate keys (audit, usage, bundle, SCIM),
   and write a post-incident review within ten working days with actions and owners.
