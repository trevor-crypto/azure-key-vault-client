use ureq::Agent;
use url::Url;

pub use crate::client::identity::IdentityConfig;
use crate::client::identity::Token;
use crate::client::types::EncryptionAlgorithm;

pub mod types;

mod identity;
mod key;
mod secret;

const API_VERSION: &str = "api-version=7.2";

pub struct KeyVaultClient {
    vault_url: Url,
    auth_scope: String,
    agent: Agent,
    identity_config: IdentityConfig,
    access_token: Option<Token>,
}

impl KeyVaultClient {
    pub fn new(vault_url: &str, identity_config: IdentityConfig) -> Result<KeyVaultClient, Error> {
        let agent = ureq::AgentBuilder::new().build();

        let vault_url = Url::parse(vault_url)?;
        let mut auth_scope = extract_endpoint(&vault_url)?;
        auth_scope.push_str("/.default");

        Ok(Self {
            agent,
            auth_scope,
            vault_url,
            access_token: None,
            identity_config,
        })
    }
}

/// ex. `https://vault.azure.net/` where the full client url is `https://myvault.vault.azure.net`
fn extract_endpoint(url: &Url) -> Result<String, Error> {
    let endpoint = url
        .host_str()
        .ok_or_else(|| Error::DomainParse(url.to_string()))?
        .split_once('.')
        .ok_or_else(|| Error::DomainParse(url.to_string()))?
        .1;
    Ok(format!("{}://{}", url.scheme(), endpoint))
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Any error generated from ureq
    #[error("HttpClient error: {0}")]
    HttpClient(#[from] ureq::Error),
    #[error("Io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("Invalid EncryptionAlgorithm: {0}")]
    EncryptionAlgorithmMismatch(EncryptionAlgorithm),
    #[error("Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Failed to parse domain: {0}")]
    DomainParse(String),
}

#[allow(clippy::option_env_unwrap)]
#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) struct Env<'a> {
        pub client_id: &'a str,
        pub client_secret: &'a str,
        pub tenant_id: &'a str,
        pub vault_url: String,
        pub key_name: &'a str,
        pub key_version: &'a str,
        pub secret_name: &'a str,
        pub secret_version: &'a str,
    }

    pub(crate) fn get_env() -> Env<'static> {
        let client_id = option_env!("AZURE_KEYVAULT_CLIENT_ID").expect("client id env var");
        let client_secret =
            option_env!("AZURE_KEYVAULT_CLIENT_SECRET").expect("client secret env var");
        let tenant_id = option_env!("AZURE_KEYVAULT_TENANT_ID").expect("tenant id env var");
        let vault_name = option_env!("AZURE_KEYVAULT_VAULT_NAME").expect("vault name env var");
        let key_name = option_env!("AZURE_KEYVAULT_KEY_NAME").expect("key name env var");
        let key_version = option_env!("AZURE_KEYVAULT_KEY_VERSION").expect("key version env var");
        let secret_name = option_env!("AZURE_KEYVAULT_SECRET_NAME").expect("secret name env var");
        let secret_version =
            option_env!("AZURE_KEYVAULT_SECRET_VERSION").expect("secret version env var");

        let vault_url = format!("https://{}.vault.azure.net", vault_name);
        Env {
            client_id,
            client_secret,
            tenant_id,
            vault_url,
            key_name,
            key_version,
            secret_name,
            secret_version,
        }
    }

    #[test]
    fn can_extract_endpoint() {
        let suffix =
            extract_endpoint(&Url::parse("https://myvault.vault.azure.net").unwrap()).unwrap();
        assert_eq!(suffix, "https://vault.azure.net");

        let suffix =
            extract_endpoint(&Url::parse("https://myvault.mycustom.vault.server.net").unwrap())
                .unwrap();
        assert_eq!(suffix, "https://mycustom.vault.server.net");

        let suffix = extract_endpoint(&Url::parse("https://myvault.internal").unwrap()).unwrap();
        assert_eq!(suffix, "https://internal");

        let suffix =
            extract_endpoint(&Url::parse("some-scheme://myvault.vault.azure.net").unwrap())
                .unwrap();
        assert_eq!(suffix, "some-scheme://vault.azure.net");
    }
}
