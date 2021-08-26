use crate::client::identity::BearerAuthExt;
use crate::client::API_VERSION;
use crate::types::KeyVaultSecret;
use crate::{Error, KeyVaultClient};

impl KeyVaultClient {
    /// Get a specified secret from a given key vault.
    /// https://docs.microsoft.com/en-us/rest/api/keyvault/get-secret/get-secret
    pub fn get_secret(
        &mut self,
        secret_name: &str,
        secret_version: Option<&str>,
    ) -> Result<KeyVaultSecret, Error> {
        self.refresh_token_access()?;

        let mut path = self.vault_url.clone();
        let rel = if let Some(secret_version) = secret_version {
            format!("secrets/{}/{}", secret_name, secret_version)
        } else {
            format!("secrets/{}", secret_name)
        };

        path.set_path(&rel);
        path.set_query(Some(API_VERSION));

        let key = self
            .agent
            .get(path.as_str())
            .set_auth(&self.bearer_auth())
            .call()?
            .into_json::<KeyVaultSecret>()?;
        Ok(key)
    }

    /// Sets a secret in a specified key vault.
    /// https://docs.microsoft.com/en-us/rest/api/keyvault/set-secret/set-secret
    pub fn set_secret(
        &mut self,
        secret_name: &str,
        secret: KeyVaultSecret,
    ) -> Result<KeyVaultSecret, Error> {
        self.refresh_token_access()?;

        let mut path = self.vault_url.clone();
        path.set_path(&format!("secrets/{}", secret_name));
        path.set_query(Some(API_VERSION));

        let json = serde_json::to_value(secret)?;

        let key = self
            .agent
            .put(path.as_str())
            .set_auth(&self.bearer_auth())
            .send_json(json)?
            .into_json::<KeyVaultSecret>()?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::client::identity::IdentityConfig;
    use crate::client::tests::get_env;
    use crate::types::SecretProperties;

    #[test]
    fn test_get_secret() {
        let env = get_env();
        let config = IdentityConfig::new(env.client_id, env.client_secret, env.tenant_id);

        let mut client = KeyVaultClient::new(&env.vault_url, config).unwrap();

        assert!(client.get_secret(env.secret_name, None).is_ok());
    }

    #[test]
    #[ignore = "sets secret"]
    fn test_set_secret() {
        let env = get_env();
        let config = IdentityConfig::new(env.client_id, env.client_secret, env.tenant_id);

        let mut client = KeyVaultClient::new(&env.vault_url, config).unwrap();

        let secret = KeyVaultSecret {
            properties: SecretProperties::default(),
            value: "secret message".to_string(),
        };
        assert!(client.set_secret(env.secret_name, secret).is_ok());
    }
}
