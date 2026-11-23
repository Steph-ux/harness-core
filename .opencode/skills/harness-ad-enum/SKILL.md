---
name: harness-ad-enum
description: "Enumerate Active Directory safely from an approved domain-joined foothold, read-only, without destructive writes."
---

# AD enumeration

Source: `active-directory-enumeration`, `bloodhound-collection`.

## Gate

An approved domain, domain-joined foothold, and test identity must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Read-only only: no password writes, no ACL changes, no GPO pushes. The permanent authorizations apply (dump read, CVE exploit) but never beyond the approved forest.

## Steps

1. Record domain, foothold, and test identity. Note the DC(s) already in evidence.
2. LDAP read-only sweep from the foothold (approved credential only):

```text
ldapsearch -x -H ldap://<dc> -D <identity> -w <pass> -b <base> "(objectClass=user)" dn | head -n 200
ldapsearch -x -H ldap://<dc> -b <base> "(objectClass=computer)" dn | head -n 200
```

Or BloodHound collection read-only (when `bloodhound-ce` / `SharpHound` is on PATH and the scope allows it): `bloodhound-ce -c All --zip <evidence-dir>/bh.zip`. Record one observation per collection.

3. Enumerate groups, trusts, SPNs (Kerberoastable), and AS-REP roastable accounts from the LDAPS output already collected. Do not request TGTs unless the scope explicitly allows authentication probing.
4. One Kerberoast/AS-REP request only when the scope allows auth: record the ticket observation. The ticket hash is stored, never the plaintext secret branch.
5. ACL/GPO findings are candidates until a read-only ACL dump (`Get-Acl` / `ldapsearch` ACL attributes) and a second observation on a different DC agree. No write is ever the proof.

Every finding is `cyber_finding` with its `evidence` observation ids, `sources` chunk ids (via `cyber_source`), and `checks` (collection / second-DC control / auth negative-control when applicable).

### Graph coverage

Build the read-only graph of users, groups, computers, trusts, SPNs, delegation,
GPOs, ACLs, sessions and local-admin edges. Separate stale, disabled and active
principals; directory presence does not prove an active credential. Correlate
BloodHound edges with LDAP attributes and, when approved, a second DC.

### Controls and secret handling

Use a known-disabled account, a non-delegated service account and a denied LDAP
query as controls. Do not spray, crack, modify passwords, request unapproved
tickets, change ACLs or execute lateral commands. Ticket material and hashes
remain restricted; the ledger records hashes/locations, never plaintext secrets.

## Done

Evidence holds the LDAP/BloodHound observations and the deduplicated principal list. A Kerberoastable or trust finding cites two DC observations.
