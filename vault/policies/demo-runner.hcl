# The broker issues single-use AppRole SecretIDs. It cannot directly read database credentials.
# The existing per-identity policies still authorize each scenario's database credential request.
path "auth/approle/role/app/role-id" { capabilities = ["read"] }
path "auth/approle/role/app/secret-id" { capabilities = ["update"] }
path "auth/approle/role/analyst/role-id" { capabilities = ["read"] }
path "auth/approle/role/analyst/secret-id" { capabilities = ["update"] }
path "auth/approle/role/admin/role-id" { capabilities = ["read"] }
path "auth/approle/role/admin/secret-id" { capabilities = ["update"] }
path "auth/approle/role/monitor/role-id" { capabilities = ["read"] }
path "auth/approle/role/monitor/secret-id" { capabilities = ["update"] }
