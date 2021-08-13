use crate::client::identity::BearerAuthExt;
use crate::client::types::{KeyVaultKey, SignRequest, SignResult, SignatureAlgorithm};
use crate::client::{Client, Error, API_VERSION};

impl Client {
    /// Gets the public part of a stored key.
    /// https://docs.microsoft.com/en-us/rest/api/keyvault/get-key/get-key
    pub fn get_key(
        &mut self,
        key_name: &str,
        key_version: Option<&str>,
    ) -> Result<KeyVaultKey, Error> {
        self.refresh_token_access()?;

        let mut path = self.vault_url.clone();
        let rel = if let Some(ver) = key_version {
            format!("keys/{}/{}", key_name, ver)
        } else {
            format!("keys/{}", key_name)
        };
        path.set_path(&rel);
        path.set_query(Some(API_VERSION));

        let key = self
            .agent
            .get(path.as_str())
            .set_auth(&self.bearer_auth())
            .call()?
            .into_json::<KeyVaultKey>()?;
        Ok(key)
    }

    /// Imports an externally created key, stores it, and returns key parameters
    /// and attributes to the client. https://docs.microsoft.com/en-us/rest/api/keyvault/import-key/import-key
    pub fn import_key(&mut self, key_name: &str, key: KeyVaultKey) -> Result<KeyVaultKey, Error> {
        self.refresh_token_access()?;

        let mut path = self.vault_url.clone();
        path.set_path(&format!("keys/{}", key_name));
        path.set_query(Some(API_VERSION));

        let json = serde_json::to_value(key)?;
        let key = self
            .agent
            .put(path.as_str())
            .set_auth(&self.bearer_auth())
            .send_json(json)?
            .into_json::<KeyVaultKey>()?;
        Ok(key)
    }

    /// Creates a signature from a digest using the specified key.
    /// https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign
    pub fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        key_name: &str,
        key_version: &str,
        digest: &str,
    ) -> Result<SignResult, Error> {
        self.refresh_token_access()?;

        let mut path = self.vault_url.clone();
        path.set_path(&format!("keys/{}/{}/sign", key_name, key_version));
        path.set_query(Some(API_VERSION));

        let req = SignRequest {
            alg: algorithm,
            value: digest.to_string(),
        };

        let json = serde_json::to_value(req)?;
        let res = self
            .agent
            .post(path.as_str())
            .set_auth(&self.bearer_auth())
            .send_json(json)?
            .into_json::<SignResult>()?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::identity::IdentityConfig;
    use crate::client::tests::get_env;

    #[test]
    fn test_get_key() {
        let env = get_env();
        let config = IdentityConfig::new(env.client_id, env.client_secret, env.tenant_id).unwrap();

        let mut client = Client::new("https://vault-test-sign.vault.azure.net/", config).unwrap();

        assert!(client.get_key(env.key_name, Some(env.key_version)).is_ok());
    }
}
