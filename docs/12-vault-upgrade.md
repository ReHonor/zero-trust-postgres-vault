# Vault 2.2.1 upgrade

## Isolated compatibility verification

Tested on the Oracle Ubuntu ARM64 VM using a separate project,
fresh credentials and certificates, separate volumes and loopback ports.

Verified:
- Fresh startup and database bootstrap password rotation.
- AppRole authentication and dynamic database credential issuance.
- All seven demo scenarios: unique identities, privilege restrictions,
  Vault policy denial, plaintext rejection, expiry rejection and auditing.
- All eight dashboard smoke checks.
- Recovery after restarting dev-mode Vault: the initial database
  authentication failure triggered bootstrap password recovery,
  cleanup and reconfiguration.
- Dashboard checks and a new analyst query passed after recovery.

## Vulnerability findings

The previous CI scan of Vault 1.21.4 reported 85 package findings.
The local ARM64 scan of Vault 2.2.1 with Trivy 0.76.1 reported two
HIGH findings for CVE-2026-116587 and no CRITICAL findings.
The remaining packages were go-jose/v3 3.0.5 and go-jose/v4 4.1.5.
The v4 finding listed 4.1.6 as a fix; the v3 finding listed no fix.

The scans used different architectures and are not a controlled
measurement of the upgrade alone. CI must rescan its selected image.

No vulnerability exception or severity reduction was added.
The upgrade reduces reported findings but does not make the image
pass the existing strict gate.

## Operational behavior

Dev-mode Vault loses its state on restart. start.sh invokes the existing
recovery procedure when the rotated database password is unavailable.
Temporary identities and dashboard authentication are recreated.
Database data remains in the existing PostgreSQL volume.
