# Automated security checks

Workflow: .github/workflows/security.yml
Triggers: pushes, pull requests and manual runs.
Execution: GitHub-hosted runners; no Oracle VM access or lab secrets.

## Checks
- Bash and Python syntax.
- Nine monitoring tests on Python 3.8 and 3.12.
- Four Gitleaks exception tests and a full fetched-history scan.
- Trivy HIGH/CRITICAL configuration findings.
- Trivy HIGH/CRITICAL vulnerabilities in the custom PostgreSQL, client
  and dashboard images, plus hashicorp/vault:2.2.1.
- Unfixed image vulnerabilities remain included.

## Exceptions and scope
Gitleaks keeps its standard rules and adds literal credential detection
for environment files. Its custom rule allows only welcome2024 in
baseline/.env.baseline. The exception is rule-specific and requires
both path and value to match. Four controlled tests verify its scope.

Two path-specific AVD-DS-0002 exceptions are recorded in
.trivyignore.yaml and selected through trivy-config.yaml:
- postgres/Dockerfile: root prepares certificate permissions at startup;
  the running database process was verified as UID/GID 999.
- baseline/attacker/Dockerfile: root supports the current privileged
  packet-capture implementation in this lab-only toolbox.

These exceptions accept the current design and require review if startup
or capture behavior changes. Other checks and image vulnerabilities are
not exempted. Trivy is explicitly set to v0.76.1.
The intentionally insecure baseline Dockerfiles remain in config scope;
its database and toolbox images are not covered by the image jobs.
Trivy configuration scanning covers supported formats, not every
security property of Compose, PostgreSQL, Vault or application code.

Passing checks do not establish that the deployed VM is secure.
The workflow does not start the lab, deploy or publish images.
Action and image version tags are used; immutable digest/SHA pinning
remains a future hardening improvement.

## Initial image investigation
The client scan reported 45 HIGH package/CVE findings across nine
distinct CVEs. A temporary candidate built with available OS package
updates and scanned with Trivy 0.76.1 still reported 45 findings and
no listed fixes. The candidate change was not added to the Dockerfile.

Image scans now write JSON and publish compact job summaries.
HIGH/CRITICAL findings, including unfixed findings, still fail the jobs.
Investigation of all four image reports remains pending.
