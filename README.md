![Crates.io](https://img.shields.io/crates/v/azure-key-vault-client?style=flat-square)
![docs.rs](https://img.shields.io/docsrs/azure-key-vault-client?style=flat-square)

# azure-key-vault-client
Minimal Sync Client for Azure Key Vault

Please see this [example](examples/client.rs) to get started.
```Rust

    // Setup identity for getting access token
    let identity_config = IdentityConfig::new("[client_id]", "[client_secret]", "[tenant_id]");

    // Initialize the client
    let client = KeyVaultClient::new("https://myvault.vault.azure.net", identity_config)?;

    // Make some requests!
    let key = client.get_key(key_name, key_version)?;
    let secret = client.get_secret(secret_name, secret_version)?;
 ```
