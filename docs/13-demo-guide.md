# Suggested five-minute presentation

## 1. Problem and architecture
Explain the shared-password baseline: broad privileges, no TLS and weak
accountability. Show the README diagram and describe Vault's role.

## 2. Demonstrate the protections
Run `bash demo.sh` and explain:
1. Two requests receive different temporary usernames and use TLS.
2. Analysts can read permitted data but cannot read national IDs or update orders.
3. The application can insert, but DELETE and DROP are denied.
4. The application cannot request administrator credentials.
5. Plaintext database connections are rejected.
6. A stolen credential is rejected after its lease expires.
7. Audit entries attribute successful SQL to temporary usernames.
   Denied attempts appear in PostgreSQL error logs.

## 3. Show the supporting evidence
Show the dashboard, docs/09-baseline-findings.md and the monitoring rules.
Explain that monitoring reports suspicious patterns; it does not prove an attack.

## 4. Close with limitations
Show GitHub Actions honestly: functional and secret-scanning checks pass,
while unresolved image findings remain visible.
Mention Vault development mode, HTTP, secret delivery and privileged Docker access.

Avoid claims such as "unhackable", "no secrets exist" or "production-ready".
The result is a tested lab demonstrating several layers of access control.
