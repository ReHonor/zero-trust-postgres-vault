# Identity "admin": may only request its own dynamic database credential.
# Everything not listed here is denied.
path "database/creds/admin" {
  capabilities = ["read"]
}
