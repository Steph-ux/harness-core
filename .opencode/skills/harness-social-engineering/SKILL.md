---
name: harness-social-engineering
description: "Run an authorized phishing or pretext simulation against an approved recipient list with canary credentials only, aggregate metrics, and stop at the first real credential."
---

# Social engineering — authorized simulation, canary only

Source: `social-engineering-assessment`, `phishing-simulation`. This method
replaces the previous `not-covered` entry. It evaluates a human control, not a
person: the deliverable is a rate and a gap, never an individual.

## Gate

Written authorization from the organization, an approved recipient list, and
an informed HR/legal owner are required. Every command goes through
`cyber_process` with `argv`. Do not build a shell string. No external third
party, no malware attachment, no availability impact, no pretext built from
personal data of a named individual. The credential endpoint stores only a
hash and a timestamp, never the submitted secret.

Stop at the first real credential submitted: destroy the capture, notify the
owner, and do not continue the campaign. Stop on any recipient outside the
list, or any use of material obtained outside the approved list.

## Steps (each step writes into `<evidence-dir>` and is its own observation)

1. Record the approval reference, the recipient list hash, the campaign window
   and the control recipient. Completion: one source chunk names all four.
2. Build the canary endpoint so a submission records `sha256(password)` plus a
   timestamp and nothing else. Prove it with a test submission and show the
   stored record contains no plaintext.
3. Send one campaign, one pretext class, no personalization from outside the
   list. Record the send count per recipient hash.
4. Measure delivery, click and canary submission as three separate counts.
   Each is its own observation; an open is not a click.
5. Negative controls: the control recipient never receives the message, a test
   address outside the window is discarded, and a submission with an empty
   password is not counted. These show the endpoint and the filter work.
6. Destroy the canary captures with the destruction command recorded in step 2,
   and show the store is empty.

## Done

Evidence holds the approval reference, the canary store proof, the three
aggregate counts, the control misses and the destruction proof. No individual
is named. A `cyber_finding` states the control that failed, the rate, and the
approved remediation path; one click without its control stays a candidate.
