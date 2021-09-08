#![allow(unused_variables)]

use azure_key_vault_client::{IdentityConfig, KeyVaultClient};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup identity for getting access token
    let identity_config = IdentityConfig::new("[client_id]", "[client_secret]", "[tenant_id]");

    // Initialize the client
    let client = KeyVaultClient::new("https://myvault.vault.azure.net", identity_config)?;

    // Make some requests!
    // client.get_key(key_name, key_version)
    // client.get_secret(secret_name, secret_version)

    Ok(())
}
