# Safe YOLO Policy v0.2

## Purpose

Allow useful agent work by default while mechanically preventing regret, resentment, irreversible loss, secret exposure, and actions that conflict with the Navigator's workflow.

## Decision classes

- **Green**: local, recoverable, task-aligned; run autonomously.
- **Blue**: externally visible or consequential, but proven safe by a deterministic contract; run and report.
- **Amber**: missing proof or requiring human judgment; require an exact, scoped capability.
- **Red**: unacceptable inside an agent session; block without override.
- **Method block**: the outcome may be valid, but the mechanism is opaque or incongruent; use a reviewable method.

## Locked constitutional decisions

1. Force push is always Red, including `--force-with-lease` and forced refspecs.
2. Permanent deletion is Red. Agents clean up through recoverable quarantine.
3. Safe feature pushes and full pull-request creation are Blue; drafts are not required.
4. Production deployment is Blue only when its complete release contract is satisfied. Otherwise it is Amber.
5. Harness changes require an expiring, scope-bound Maintenance capability.
6. Literal credential-free public HTTP(S) reads are Green. Dynamic, redirected, authenticated, private, mutating, or executable network activity receives stricter treatment.
7. Task-aligned, non-bulk, non-administrative Core and Linear writes are Green.

## Capability invariants

A capability must bind:

- session;
- action or maintenance kind;
- canonical repository or harness;
- exact target or permitted scopes;
- expiry.

Capabilities cannot override constitutional Red actions and cannot be widened by the caller.

## Policy layering

```text
Constitutional Red
    -> global policy
    -> harness transport
    -> repository-local restrictions and release contract
    -> exact temporary capability
    -> current action context
```

Repository policy may make an action stricter or define how Amber earns Blue. It cannot weaken constitutional Red.

## Maintenance

Adapter Maintenance may modify only named scopes for one harness and one session. Policy Maintenance is separate and required for changes to Red classifications, capability semantics, protected surfaces, secret handling, or the canonical engine.

Opaque inline mutation remains Method-blocked even during Maintenance Mode.

## Safety versus validation

Safety decides whether an action may harm the Navigator's world. Validation decides whether completed work meets project standards. They are separate systems, although validation evidence may promote a deployment from Amber to Blue.
