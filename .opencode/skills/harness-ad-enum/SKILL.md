---
name: harness-ad-enum
description: "Enumerate an approved Active Directory forest read-only from a named foothold: LDAP/BloodHound, optional scoped Kerberoast, two-DC confirmation, no writes."
---

# AD enumeration

Source: LDAP, BloodHound CE, Kerberos. Writes, sprays, and ACL changes are out.

## Gate

An approved domain, domain-joined foothold, and test identity must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Read-only: no password writes, no ACL changes, no GPO pushes, no unconstrained ticket requests. Stay in the approved forest.

## Steps

### 1. Name the forest

Record domain, foothold, test identity, and DC(s) already in evidence.

### 2. LDAP read-only (approved bind only)

```
cyber_process argv=["ldapsearch","-x","-H","ldaps://<dc>","-D","<identity>","-y","<restricted-password-file>","-z","200","-l","10","-b","<base>","(objectClass=user)","dn"]
cyber_process argv=["ldapsearch","-x","-H","ldaps://<dc>","-D","<identity>","-y","<restricted-password-file>","-z","200","-l","10","-b","<base>","(objectClass=computer)","dn"]
```

Cap the output (head via the tool's own size, not a piped shell). Prefer LDAPS. Record one observation per query.

BloodHound, if in PATH **and** scope allows collection:

```
cyber_process argv=["<approved-bloodhound-collector>","--help"]
```

This is preflight, not collection evidence. Identify the installed collector,
its authentication input and bounded collection options before using it.
The BloodHound CE server executable is not assumed to be a collector.

### 3. Graph without roasting yet

From the LDAP/BH output: groups, trusts, SPNs (Kerberoastable **candidates**), AS-REP roastable **candidates**, delegation, GPOs. Directory presence ≠ active credential. Separate disabled/stale.

### 4. Auth probing only if the scope says so

One Kerberoast or AS-REP request **only** when authentication probing is explicit. Store the **hash**, never plaintext. Cracking is out of this method unless separately approved.

### 5. Negative control and second DC

- known-disabled account
- denied LDAP query
- second DC must agree before an ACL/GPO finding

A write is never the proof.

### 6. Finding contract

`cyber_finding` with collection observation, second-DC or denied-query control, source chunks. Ticket material stays restricted in the ledger (hash/location only).

### What stays hashed

TGS/AS-REP material: path + SHA256 in the ledger, never the `$krb5tgs$` blob in a finding title. Cracking is a separate approval.

### Graph rows

Users, groups, computers, trusts, SPNs, unconstrained delegation, GPOs, ACLs. Presence ≠ live credential. Disabled/stale separated.

```
cyber_process argv=["ldapsearch","-x","-H","ldaps://<dc2>","-D","<identity>","-y","<restricted-password-file>","-z","200","-l","10","-b","<base>","(objectClass=user)","dn"]
```

Second DC is the confirmation observation, not a second forest. A write is never the proof. Disabled and stale principals are listed separately from live credentials.

### Stop

Password spray, `Add-ADGroupMember`, GPO edit, DCSync unless the letter names it, tickets for accounts not in the test set.

### Evidence ids

LDAP/BH collection, second-DC or denied-query control. Ticket hashes only. Finding title names the principal class (SPN, trust, ACL), not a password.

### LDAPS only

Prefer `ldaps://`. Plain LDAP is `not-tested` unless the letter allows it. Cap result size in the tool, not with a piped `head`.

```
cyber_process argv=["ldapsearch","-x","-H","ldaps://<dc>","-D","<identity>","-y","<restricted-password-file>","-z","200","-l","10","-b","<base>","(objectClass=computer)","dn"]
```

BloodHound `-c All` only if PATH and scope allow. Kerberoast/AS-REP: one request, hash only, cracking out unless approved.

### Stop

Spray, Add-ADGroupMember, GPO edit, DCSync unless named, tickets for non-test accounts.

## Verification scenarios

Record the LDAP base DN, bind principal, server and collection time.
Use the installed collector's documented flags: a BloodHound server is not its collector.
Pass authentication through its supported protected input, not a password in argv.
Set the LDAP size and time limits explicitly; truncation is incomplete coverage.

| Scenario | Evidence compared | Expected classification |
|---|---|---|
| User has an SPN but no ticket was requested | directory attributes | roastable candidate, no credential compromise |
| Two DCs return different ACLs | object GUID, replication and timestamps | unresolved replication difference |
| Authenticated query works; anonymous twin is denied | same base and filter | observed negative control |
| Disabled account appears in a graph path | account status plus graph edge | inactive path distinguished |
| Collector cannot page all results | size-limit response | partial collection, not empty directory |

A second agreeing DC corroborates state; it is not a negative control.
An ACL finding names the trustee SID, inherited scope and effective right.
Keep ticket acquisition, cracking and directory write privileges separate in coverage.
The packet includes collection, corroboration, denial and the relevant graph/source chunk.

## Done

Evidence holds LDAP/BloodHound observations and the principal list. A Kerberoastable or trust finding cites two DC observations or a denied-query control.
