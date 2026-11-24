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
cyber_process argv=["ldapsearch","-x","-H","ldaps://<dc>","-D","<identity>","-b","<base>","(objectClass=user)","dn"]
cyber_process argv=["ldapsearch","-x","-H","ldaps://<dc>","-D","<identity>","-b","<base>","(objectClass=computer)","dn"]
```

Cap the output (head via the tool's own size, not a piped shell). Prefer LDAPS. Record one observation per query.

BloodHound, if in PATH **and** scope allows collection:

```
cyber_process argv=["bloodhound-ce","-c","All","--zip","<evidence-dir>/bh.zip"]
```

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
cyber_process argv=["ldapsearch","-x","-H","ldaps://<dc2>","-D","<identity>","-b","<base>","(objectClass=user)","dn"]
```

Second DC is the confirmation observation, not a second forest. A write is never the proof. Disabled and stale principals are listed separately from live credentials.

### Stop

Password spray, `Add-ADGroupMember`, GPO edit, DCSync unless the letter names it, tickets for accounts not in the test set.

### Evidence ids

LDAP/BH collection, second-DC or denied-query control. Ticket hashes only. Finding title names the principal class (SPN, trust, ACL), not a password.

## Done

Evidence holds LDAP/BloodHound observations and the principal list. A Kerberoastable or trust finding cites two DC observations or a denied-query control.
