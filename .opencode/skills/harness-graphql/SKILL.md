---
name: harness-graphql
description: "Assess an approved GraphQL endpoint: introspection, allowed field, forbidden field, one bounded depth and one batch; HTTP 200 with data:null is not bypass."
---

# GraphQL — introspection, BOLA, depth/batching

Source: GraphQL security. Disabled `__schema` is a control, not a vuln. One batch only (DoS).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Endpoint in scope. One extra depth query and one batch unless the scope allows more. No unbounded aliases. Mutations only on an owned test object, then restore.

## Steps

### 1. Introspection

```
cyber_process argv=["curl","-sS","-H","Content-Type: application/json","--data-binary","{\"query\":\"{__schema{types{name}}}\"}","<graphql-url>"]
```

Refusal = control. If disabled, harvest from client/sourcemap `endpoints.json`.

### 2. Allowed vs forbidden

Pick `me{email}` vs `user(id:"<other>"){email}` (or the schema's equivalent). Allowed → positive control. Forbidden with same identity: data returned = candidate; `{"errors":...,"data":null}` is not.

### 3. Depth and batch — one each

Depth `{a{a{a{a{id}}}}}` and one JSON array of two queries. Timeout: measure vs a shallow baseline (`diff-control`). A single slow request is not a finding.

### 4. Negative control

Unauth introspection (if auth is required) must fail. A known-invalid field must error. Do not load-test.

### 5. Finding contract

`cyber_finding` with introspection, allowed, forbidden, optional depth/batch. Schema/CURL chunk as `cyber_source`. Checks: allowed positive, forbidden reproduction, unauth/invalid negative. Persisted-query access is proven by the **returned field**, not by a hash being accepted.

## Proof contract

A GraphQL finding cites schema/client source, allowed positive control, forbidden or cross-tenant reproduction, and the invalid-field or unauth control.

HTTP 200 with `data:null` is not bypass. Depth/batching needs bounded impact, never one slow request. Persisted-query access is the returned field, not a hash being accepted.

### Query shapes

```
cyber_process argv=["curl","-sS","-H","Content-Type: application/json","--data-binary","{\"query\":\"{ me { email } }\"}","<url>"]
cyber_process argv=["curl","-sS","-H","Content-Type: application/json","--data-binary","{\"query\":\"{ user(id:\\\"<other>\\\") { email } }\"}","<url>"]
```

Compare `data` vs `errors` vs `null`. Aliases/fragments: one extra if the simple field is clean.

| Check | Positive | Negative |
|---|---|---|
| Introspection | schema types | unauth reject if auth required |
| Allowed field | `me.email` | n/a |
| Forbidden | other-user email | `data:null` + errors |
| Depth | bounded 4 | shallow baseline timing |
| Batch | 2 queries | 1 query |

Do not send 100 aliases. One batch of two queries is the DoS ceiling. A single slow request is not depth/batching proof. Mutations only on an owned object, then restore.

### Evidence ids

Introspection, allowed, forbidden, optional depth/batch. `contains` is the leaked field in `data`, not HTTP 200. `data:null` is the negative control.

### Mutations

Owned test object, reversible marker, re-read, restore. Persisted query: proof is the returned field, not the hash being accepted.

### Stop

100 aliases, unbounded batch, load-test, treating `data:null` as bypass.

### Depth ceiling

Four nested fields max. Batch = two queries. Shallow query is the timing baseline. HTTP 200 + `data:null` is the negative control, not bypass.

```
cyber_process argv=["curl","-sS","-H","Content-Type: application/json","--data-binary","{\"query\":\"{ me { email } }\"}","<url>"]
```

Disabled `__schema` is a control. Harvest from client if needed. Mutations: owned object, restore.

### Stop

100 aliases, unbounded batch, load-test.

## Verification scenarios

Construct queries from the actual schema; `a{a{...}}` is only a shape illustration.
Use two owned test accounts and distinguish object-level from field-level authorization.
Inspect partial `data` even when the response also contains `errors`.

| Scenario | Observation | Expected classification |
|---|---|---|
| Private field is null but an unrelated public field is returned | field paths and errors | private field denial holds |
| Other synthetic user's private field is returned | owner baseline and cross-account query | authorization candidate |
| Alias requests the same private field | resolver result and matching denial twin | alias does not create permission |
| Batch of two queries is accepted | both operation results | feature support, not DoS |
| Depth probe names nonexistent fields | validation errors | invalid probe, not depth enforcement |

Introspection availability alone is not a vulnerability.
A clean invalid-field error validates parsing, not object authorization.
Persisted-query registration and execution authorization are separate boundaries.
Mutation proof requires an independent read under the object owner's identity.
Attach query variables, operationName, actor and exact returned field path.

## Done

Cites introspection, allowed, forbidden, single depth/batch. Disabled introspection is not a finding. Untested mutations stay `not-tested`.
