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
  and dashboard images, plus hashicorp/vault:1.21.4.
- Unfixed image vulnerabilities remain included.

## Exceptions and scope
Gitleaks keeps its standard rules and adds literal credential detection
for environment files. Its custom rule allows only welcome2024 in
baseline/.env.baseline. The exception is rule-specific and requires
both path and value to match. Four controlled tests verify its scope.

No project-specific Trivy exceptions have been added.
Initial findings must be reviewed before exceptions are considered.
The intentionally insecure baseline Dockerfiles remain in config scope;
its database and toolbox images are not covered by the image jobs.
Trivy configuration scanning covers supported formats, not every
security property of Compose, PostgreSQL, Vault or application code.

Passing checks do not establish that the deployed VM is secure.
The workflow does not start the lab, deploy or publish images.
Action and image version tags are used; immutable digest/SHA pinning
remains a future hardening improvement.
