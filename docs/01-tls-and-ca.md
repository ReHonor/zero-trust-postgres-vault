# 01 - TLS and the private Certificate Authority

## Goal
Let clients verify that they are talking to the real PostgreSQL server (defense against man-in-the-middle).

## What `scripts/gen-certs.sh` produces (in `certs/`, git-ignored)
| File | Purpose | Who may have it |
|---|---|---|
| ca.key | CA private key, can sign any certificate | Nobody but the host that generates certs |
| ca.crt | CA public certificate, the trust anchor | PostgreSQL, Vault, client |
| server.key | Server private key | PostgreSQL only |
| server.crt | Server certificate signed by the CA | PostgreSQL (sent to clients in the handshake) |

## Design decisions
- Valid hostnames are in the SAN (`postgres`, `localhost`, `127.0.0.1`), because modern clients ignore the CN.
- `CA:FALSE` and `serverAuth` restrict what the server certificate can be used for.
- CA properties are defined in a config file (`ca.cnf`) and the certificates carry key identifiers (SKI/AKI) so the chain is explicit.
- No CA passphrase: acceptable for a lab. In production use an offline CA or Vault PKI.

## Verification
- `openssl verify -CAfile certs/ca.crt certs/server.crt` returns OK.
- Certificate and key moduli match.
- A certificate verified against a fake CA with the same name fails: trust comes from the signature, not from the name.

## Troubleshooting log
### `error 20 at 0 depth lookup: unable to get local issuer certificate`
- Symptom: `openssl verify` failed although the issuer name matched the CA subject.
- Diagnosis: `openssl x509 -in certs/ca.crt -noout -text` showed `Basic Constraints` twice. The system `openssl.cnf` already adds it, and the first script added it again with `-addext`.
- Cause: a duplicated extension cannot be decoded, so OpenSSL does not accept the CA as a valid issuer.
- Fix: define the CA extensions in a dedicated `ca.cnf` passed with `-config` (replaces the system defaults) and check that each extension appears once.
