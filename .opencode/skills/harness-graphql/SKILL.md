---
name: harness-graphql
description: "Assess an approved GraphQL endpoint by comparing introspection, an allowed field, and a field the test identity must not read."
---

# GraphQL — introspection, BOLA, depth/batching

Source: `performing-graphql-security-assessment` (2024: `__schema` disabled → BOLA via persisted queries).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Endpoint in scope. Depth/batching/mutation: one extra each unless scope allows more. Batch is DoS vector — one batch only.

## Steps

1. Introspection `cyber_process` `argv`:
```graphql
{ __schema { types { name fields { name } } } }
```
Refusal = control not vuln. If disabled, harvest from `katana -jc` / sourcemap `endpoints.json`.

2. Pick allowed vs forbidden field (e.g. `me{email}` vs `user(id:"<other-id>"){email}`).
3. Allowed → positive control. Forbidden with same identity → record. Data returned = candidate; `{"errors":…, "data":null}` is not.
4. One depth (`{a{a{a{a{id}}}}}`) + one batch (`[{"query":"…"},…]`) — one each. Timeout after is signal; measure `diff-control --seuil-ms`.
5. `harness-vuln-triage` → `cyber_finding` with introspection+allowed+forbidden+depth observations, schema/CURL `cyber_source` chunk, `checks` allowed:positive, forbidden:reproduction, unauth-introspection:negative.

### Query coverage

Inventory queries, mutations, subscriptions, aliases, fragments, persisted
query ids, directives and batching from the schema or collected client traffic.
Select one allowed field, one same-tenant object, one other-tenant object and
one admin-only field. Test variables and inline arguments separately. Compare
`data`, `errors`, nullability and extensions; an HTTP 200 with `data:null` is
not authorization bypass.

### Resource controls

Use one bounded depth query and one bounded batch, with a known-valid shallow
query as the timing/control baseline. Do not load-test or send unbounded
aliases. Test introspection both authenticated and unauthenticated; disabled
introspection is a control, not a vulnerability. For mutations use an owned
test object and a reversible marker, then re-read and restore it.

### Proof contract

A GraphQL finding cites the schema/client source, allowed positive control,
forbidden or cross-tenant reproduction, and the negative control. Persisted
query access is proven by the returned field or state change, not by a query
hash being accepted. Depth or batching is a finding only with bounded impact
evidence and a safe control, never from a single slow request.

## Done

Cites introspection, allowed, forbidden, single depth/batching. Disabled introspection not a finding.
