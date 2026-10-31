# Identity "app": may only request its own dynamic database credential.
# Everything not listed here is denied.
path "database/creds/app" {
  capabilities = ["read"]
}
