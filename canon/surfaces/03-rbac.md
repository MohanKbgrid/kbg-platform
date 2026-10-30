# Surface 3 — RBAC (authorisation, scope, separation of duties)

**Wave 1.** Deny-by-default only holds if it is present from the first endpoint. Retrofitting
authorisation across an existing API is how projects end up with a permission model that is really
a collection of `if` statements.

## Purpose

Answer three questions for every action, in one place: **can this person do this**, **to which
rows**, and **is this action incompatible with something else they do**. Most systems answer the
first, fudge the second, and never ask the third.

## The contract

1. **Permission is checked, never inferred from a role name.** `can(actor, action, object)` is the
   only question the application asks. A role name appearing in an `if` is a defect — roles change
   name, merge, and split; permissions do not.
2. **Deny by default.** An action not granted is denied. New endpoints are therefore closed until
   someone grants them, which is the correct direction of failure.
3. **A denied action is VISIBLE WITH ITS REASON**, not hidden. Hiding teaches users the feature does
   not exist and generates support load; showing it disabled with "requires Plant Manager approval"
   teaches them how the organisation works. The same authority function drives both the button
   state and the API's 403, so **a disabled button and a rejection can never disagree**.

   **A denial carries its KIND as well as its reason.** "Not allowed" covers seven different things,
   and the person looking at a greyed-out button needs to know which, because each has a different
   next step. The kind is a closed list, and `AUTHORITY` is the default:

   | Kind | Meaning | What the person should be shown |
   |---|---|---|
   | `AUTHORITY` | Their role, scope or a segregation-of-duties rule does not allow it | Which position can, and how to ask |
   | `STATE_GATE` | The object is in a state that does not allow it (already posted, cancelled, patient not admitted) | The state it is in; nothing to request |
   | `CONFIG_GATE` | A setting or environment switch turns it off | Who can change the setting; that it is off by choice |
   | `PRECONDITION` | Something required first is missing or fails a check (a document, a master value, a limit) | Exactly what is missing |
   | `READINESS` | The system is not ready yet (data loading, a dependency down, a trust period not yet earned) | That it is temporary, and why |
   | `APPROVAL_PENDING` | Waiting on a named approver | Who, since when; the request is already in their queue |
   | `COMPLETED` | Already done | The result. This is not an error |

   A kind outside this list is refused when the decision is built, and a denial with no reason is
   refused too: a silently disabled control is the thing this rule exists to prevent.
4. **Scope is data, not code.** A person's reach — which plants, routes, territories, companies —
   is rows, resolved at decision time. Widening someone's scope is an assignment change, never a
   deploy.
5. **Roles attach to POSITIONS, people occupy positions.** When someone moves job, you change one
   assignment row; their permissions, queue, and approvals move with the position. (See D9.)
6. **Separation of duties is declared and enforced.** A conflict pair (raises payment / approves
   payment; records stock / verifies stock) is a row; holding both is refused at assignment time
   with the conflict named, not discovered in an audit.
7. **Delegation is explicit, bounded and logged.** A delegation has a grantor, a grantee, a scope,
   and an end date. Actions taken under it record **acted-for** — the audit shows both identities.
8. **Every decision is logged**, allow and deny alike. A permission system that only records denials
   cannot answer "who could have done this".

## Schema shape

```
role                  id · code · name · is_active
permission            id · code · description             ← the verbs, e.g. order.correct
role_permission       role_id · permission_id
position              id · code · title · parent_position_id · org_unit_id
principal             id · display_name · login · is_active
principal_position    principal_id · position_id · valid_from · valid_to
position_role         position_id · role_id
scope_assignment      principal_id|position_id · dimension · value   ← plant / route / company
sod_conflict          permission_a · permission_b · reason
delegation            grantor · grantee · scope · valid_from · valid_to · reason
decision_log          actor · action · object_ref · allowed · kind · reason · acted_for · at
```

## Doctrines that bind here

- **D1 deny by default** · **D5 scope is data** · **D9 route to a position** · **D2 the decision log
  is append-only**.

## What "0 principals bound to logins" means

It is a legitimate state, and worth saying out loud: you can build and gate this entire surface
before a single real user exists, because the model is about positions and permissions, not people.
Binding logins is a seeding step, not a build step. Do not let an empty `principal` table read as
an unbuilt surface.

## Gate tests

1. **A permission not granted is denied.** Add a new action; assert it is denied for every existing
   role until explicitly granted.
2. **Role names appear in no conditional.** A grep-level assertion: no role code appears in an `if`
   in application code. Crude, and it catches the real thing.
3. **Scope actually scopes.** Give a person plant A; assert they read A's rows and *not* B's — and
   assert they cannot write to B even with a valid permission.
4. **A position change moves everything, with no deploy.** Move a principal from position X to Y;
   assert their permissions, queue items, and approval authority all changed, and that nothing was
   edited but one assignment row.
5. **The button and the API agree.** For a denied action, assert the availability API says
   `enabled:false` *with a reason and a kind*, and that calling the endpoint anyway returns 403 with
   the **same** reason and the **same** kind. Both must come from one function.
6. **SoD refuses at assignment.** Attempt to give one person both halves of a conflict pair; assert
   refusal naming the conflict — not a warning, and not a later report.
7. **Delegation expires and is attributable.** Act under a delegation; assert the log records
   acted-for. Advance past the end date; assert the action is now denied.
8. **The decision log records allows too.** Perform a permitted action; assert a log row exists.
9. **A denial names its kind, and only a known one.** Produce one denial of each of the seven kinds;
   assert each response carries that kind and a non-empty reason. Try to build a denial with an
   unknown kind, and with no reason; assert both are refused.

## Divergence register

| What | Why | Cost |
|---|---|---|
| ⛔ **The engine conforms but is NOT universally applied.** 13 of 30 routers reference the authority layer; the rest are gated only by `require_user` (authenticated, not authorised). | RBAC landed as step 02 of one slice; earlier routers were never retrofitted. | **Deny-by-default does not hold across the API.** An authenticated user reaching an ungated router is not permission-checked. This is the single largest divergence in this register. |
| `principal_role` holds **0 rows** — no principal is bound to a role in this environment | Deliberate and evidence-based: role populations were seeded from real client data, but login binding waits on the client's role census. | The permission model is exercised by tests, not by real users. Correct for the build stage, but it means production behaviour is untested. |
| **The vendorable base does not carry the denial kind yet.** `bases/core/authority.py` returns a reason and a `who_can`, but no `kind`; the seven kinds are specified here and implemented in one reference product. | The kind was learned after the base was cut. It is on the base's update list (W5, item H2), with a default of `AUTHORITY` so existing callers keep working. | Until then a product vendoring the base must add the kind itself, or its screens cannot tell a state gate from a missing permission. Gate 9 will fail on the base as it stands. |
| _Conforms on_ — `can()` contract, scope-as-data, position-based roles, SoD conflicts, delegation with acted-for, decision logging (47/47). | | |
