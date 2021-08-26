use crate::client::identity::BearerAuthExt;
use crate::client::types::{KeyVaultKey, SignRequest, SignResult, SignatureAlgorithm};
use crate::client::{Error, KeyVaultClient, API_VERSION};
use crate::types::{VerifyRequest, VerifyResult};

impl KeyVaultClient {
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
    /// `digest` must be the same hash used in `algorithm`.
    /// https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign
    pub fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        key_name: &str,
        key_version: &str,
        digest: &[u8],
    ) -> Result<SignResult, Error> {
        self.refresh_token_access()?;

        let mut path = self.vault_url.clone();
        path.set_path(&format!("keys/{}/{}/sign", key_name, key_version));
        path.set_query(Some(API_VERSION));

        let req = SignRequest {
            alg: algorithm,
            value: digest.to_vec(),
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

    /// Verifies a signature using a specified key.
    pub fn verify(
        &mut self,
        algorithm: SignatureAlgorithm,
        key_name: &str,
        key_version: &str,
        digest: &[u8],
        value: &[u8],
    ) -> Result<bool, Error> {
        self.refresh_token_access()?;

        let mut path = self.vault_url.clone();
        path.set_path(&format!("keys/{}/{}/verify", key_name, key_version));
        path.set_query(Some(API_VERSION));

        let req = VerifyRequest {
            alg: algorithm,
            digest: digest.to_vec(),
            value: value.to_vec(),
        };

        let json = serde_json::to_value(req)?;
        let res = self
            .agent
            .post(path.as_str())
            .set_auth(&self.bearer_auth())
            .send_json(json)?
            .into_json::<VerifyResult>()?;

        Ok(res.value)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::client::identity::IdentityConfig;
    use crate::client::tests::get_env;

    #[test]
    fn test_get_key() {
        let env = get_env();
        let config = IdentityConfig::new(env.client_id, env.client_secret, env.tenant_id);

        let mut client = KeyVaultClient::new(&env.vault_url, config).unwrap();

        assert!(client.get_key(env.key_name, Some(env.key_version)).is_ok());
    }

    #[test]
    #[ignore = "need to change the key name every time"]
    fn test_import_key() {
        let env = get_env();

        let config = IdentityConfig::new(env.client_id, env.client_secret, env.tenant_id);

        let mut client = KeyVaultClient::new(&env.vault_url, config).unwrap();

        // test key from azure docs
        let json_key = json!({
          "key": {
            "kty": "RSA",
            "key_ops": [
                "sign"
            ],
            "n": "nKAwarTrOpzd1hhH4cQNdVTgRF-b0ubPD8ZNVf0UXjb62QuAk3Dn68ESThcF7SoDYRx2QVcfoMC9WCcuQUQDieJF-lvJTSer1TwH72NBovwKlHvrXqEI0a6_uVYY5n-soGt7qFZNbwQLdWWA6PrbqTLIkv6r01dcuhTiQQAn6OWEa0JbFvWfF1kILQIaSBBBaaQ4R7hZs7-VQTHGD7J1xGteof4gw2VTiwNdcE8p5UG5b6S9KQwAeET4yB4KFPwQ3TDdzxJQ89mwYVi_sgAIggN54hTq4oEKYJHBOMtFGIN0_HQ60ZSUnpOi87xNC-8VFqnv4rfTQ7nkK6XMvjMVfw",
            "e": "AQAB",
            "d": "GeT1_D5LAZa7qlC7WZ0DKJnOth8kcPrN0urTEFtWCbmHQWkAad_px_VUpGp0BWDDzENbXbQcu4QCCdf4crve5eXt8dVI86OSah-RpEdBq8OFsETIhg2Tmq8MbYTJexoynRcIC62xAaCmkFMmu931gQSvWnYWTEuOPgmD2oE_F-bP9TFlGRc69a6MSbtcSRyFTsd5KsUr40QS4zf2W4kZCOWejyLuxk88SXgUqcJx86Ulc1Ol1KkTBLadvReAZCyCMwKBlNRGw46BU_iK0vK7rTD9fmEd639Gjti6eLpnyQYpnVe8uGgwVU1fHBkAKyapWoEG6VMhMntcrvgukKLIsQ",
            "dp": "ZGnmWx-Nca71z9a9vvT4g02iv3S-3kSgmhl8JST09YQwK8tfiK7nXnNMtXJi2K4dLKKnLicGtCzB6W3mXdLcP2SUOWDOeStoBt8HEBT4MrI1psCKqnBum78WkHju90rBFj99amkP6UeQy5EASAzgmKQu2nUaUnRV0lYP8LHMCkE",
            "dq": "dtpke0foFs04hPS6XYLA5lc7-1MAHfZKN4CkMAofwDqPmRQzCxpDJUk0gMWGJEdU_Lqfbg22Py44cci0dczH36NW3UU5BL86T2_SPPDOuyX7kDscrIJCdowxQCGJHGRBEozM_uTL46wu6UnUIv7m7cuGgodJyZBcdwpo6ziFink",
            "qi": "Y9KD5GaHkAYmAqpOfAQUMr71QuAAaBb0APzMuUvoEYw39PD3_vJeh9HZ15QmJ8zCX10-nlzUB-bWwvK-rGcJXbK4pArilr5MiaYv7e8h5eW2zs2_itDJ6Oebi-wVbMhg7DvUTBbkCvPhhIedE4UlDQmMYP7RhzVVs7SfmkGs_DQ",
            "p": "v1jeCPnuJQM2PW2690Q9KJk0Ulok8VFGjkcHUHVi3orKdy7y_TCIWM6ZGvgFzI6abinzYbTEPKV4wFdMAwvOWmawXj5YrsoeB44_HXJ0ak_5_iP6XXR8MLGXbd0ZqsxvAZyzMj9vyle7EN2cBod6aenI2QZoRDucPvjPwZsZotk",
            "q": "0Yv-Dj6qnvx_LL70lUnKA6MgHE_bUC4drl5ZNDDsUdUUYfxIK4G1rGU45kHGtp-Qg-Uyf9s52ywLylhcVE3jfbjOgEozlSwKyhqfXkLpMLWHqOKj9fcfYd4PWKPOgpzWsqjA6fJbBUMYo0CU2G9cWCtVodO7sBJVSIZunWrAlBc"
          },
          "tags": {
            "purpose": "unit test"
          }
        });

        let key = serde_json::from_value::<KeyVaultKey>(json_key).unwrap();
        let res = client.import_key("test-key1", key);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_sign() {
        let env = get_env();
        let config = IdentityConfig::new(env.client_id, env.client_secret, env.tenant_id);

        let mut client = KeyVaultClient::new(&env.vault_url, config).unwrap();

        let digest = b"test message";
        let res = client.sign(
            SignatureAlgorithm::RSNULL,
            env.key_name,
            env.key_version,
            digest,
        );
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify() {
        let env = get_env();
        let config = IdentityConfig::new(env.client_id, env.client_secret, env.tenant_id);

        let mut client = KeyVaultClient::new(&env.vault_url, config).unwrap();

        let digest = b"test message";

        let res = client
            .sign(
                SignatureAlgorithm::RSNULL,
                env.key_name,
                env.key_version,
                digest,
            )
            .unwrap();

        let signature = res.signature;

        let res = client
            .verify(
                SignatureAlgorithm::RSNULL,
                env.key_name,
                env.key_version,
                digest,
                &signature,
            )
            .unwrap();
        println!("{:?}", res);
        assert!(res);
    }
}
