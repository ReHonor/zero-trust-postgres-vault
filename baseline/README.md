# INTENTIONALLY INSECURE baseline ("before")

This folder is the "before" half of the before/after comparison. It contains a deliberately weak setup:
a shared static password committed to Git, no TLS, an application account that is a superuser, no auditing.
All data is fake. It publishes no ports and lives on an internal Docker network. Never deploy it.

    bash baseline/run.sh up              start it (plus an attacker toolbox container)
    bash baseline/run.sh audit           attack the insecure system
    bash baseline/run.sh audit-hardened  run the same kind of probes against the zero-trust system
    bash baseline/run.sh down            delete it
