# Identity "monitor": may request its own database credential and read (not change) the role definitions.
path "database/creds/monitor" {
  capabilities = ["read"]
}
path "database/roles" {
  capabilities = ["list"]
}
path "database/roles/*" {
  capabilities = ["read"]
}
