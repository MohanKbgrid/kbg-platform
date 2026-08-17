# Surface 5 — Documents and required evidence

**Wave 2.** Workflow steps depend on it: "cannot complete without the counterfoil photo" is a
document rule, enforced by the workflow.

## Purpose

Most systems treat file upload as a feature of one screen. It is a platform surface, because the
question "what evidence must exist before this can proceed" recurs in every module and must have
one answer — otherwise each screen invents its own, and none of them block.

## The contract

1. **A document type is declared, not implied.** Each type states what it is, which object it
   attaches to, whether it is required, and at which step it becomes required.
2. **Required means BLOCKING.** If a type is required for a transition, the transition fails without
   it, with the missing type named. A "required" flag that only greys out a button is decoration.
3. **Requirements are per-tenant configuration**, because two companies genuinely differ on what
   they demand.
4. **Documents attach to an object and a step**, not to a screen. The same photo is reachable from
   the transaction, the approval, and the audit.
5. **Generated artifacts are documents too.** A printed gate pass, an exported journal, a day-close
   statement — each is stored as a document when it is produced, not regenerated on demand. What
   was handed to the driver is the thing that must be retrievable, not a fresh render that might
   now differ.
6. **Reprints are labelled.** The first print is the original; every subsequent one says DUPLICATE
   and is counted. This is a control, not a courtesy.
7. **Numbering is per company and per financial year**, allocated atomically, and gapless where the
   jurisdiction demands it. Sequence allocation is a platform concern; a module that generates its
   own numbers will collide under concurrency.
8. **Storage is content-addressed and metadata is in the database.** The blob store holds bytes; the
   database holds who, when, which object, which type, checksum. Never infer meaning from a filename.

## Schema shape

```
doc_type              key · name · object_type · is_required · required_at_step · retention
document_requirement  company_id · doc_type_key · object_type · is_required · note
document              company_id · doc_type_key · object_type · object_ref · storage_key
                      · checksum · original_filename · mime · bytes
                      · uploaded_by · uploaded_at · generated (bool) · print_count
document_sequence     company_id · series_key · fiscal_year · next_value   ← atomic allocation
```

## Doctrines that bind here

**D1** an undeclared type is rejected · **D2** documents are never edited, superseded instead ·
**D5** requirements are config · **D3** upload idempotency by client-minted id, so a retried upload
on a bad connection does not create a second copy.

## The offline case

A field app captures evidence where there is no network. Therefore: the capture id is minted on the
device and *is* the document's identity; the queue retries until acknowledged; and the same photo
flushed three times produces exactly one document. Test this by flushing the same queue repeatedly
and asserting identical counts — not by trusting the retry logic.

## Gate tests

1. **A required document blocks the transition.** Attempt the step without it; assert refusal naming
   the missing type. Attach it; assert the step now completes.
2. **Requirements are per tenant.** Make a type required for company A only; assert A blocks and B
   proceeds, with no code difference.
3. **A generated artifact is stored, not re-rendered.** Produce a printable artifact; assert a
   document row exists with a checksum; re-fetch and assert the bytes are *the stored ones*.
4. **A reprint is labelled and counted.** Print twice; assert the second is marked DUPLICATE and
   `print_count` is 2.
5. **Numbering is atomic and scoped.** Allocate concurrently from the same series; assert no
   duplicates and no gaps. Allocate for a second company; assert an independent sequence.
6. **A re-flushed capture does not duplicate.** Submit the same client-minted document id three
   times; assert one row.
7. **Metadata does not live in the filename.** Rename a stored blob; assert every read still
   resolves correctly from the database.

## Divergence register

| What | Why | Cost |
|---|---|---|
| _Conforms._ 26 declared doc types, 4 requirements, required-blocking proven, generated artifacts stored, DUPLICATE reprints counted, atomic per-company/per-FY numbering (8 sequences). 96/96. | | |
