use chrono::{DateTime, Duration, Utc};
use oauth2::{url, AccessToken, ClientId, ClientSecret};
use serde::{Deserialize, Deserializer};
use ureq::Request;

use crate::client::{Client, Error};

#[derive(Debug)]
pub(crate) struct Token {
    expires_on: DateTime<Utc>,
    access_token: AccessToken,
}

#[derive(Debug, Deserialize, Clone)]
struct TokenResponse {
    pub token_type: String,
    pub expires_in: u64,
    pub ext_expires_in: u64,
    pub expires_on: Option<DateTime<Utc>>,
    pub not_before: Option<DateTime<Utc>>,
    pub resource: Option<String>,
    #[serde(deserialize_with = "deser_access_token")]
    pub access_token: AccessToken,
}

fn deser_access_token<'de, D>(deserializer: D) -> Result<AccessToken, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(AccessToken::new(s))
}

#[derive(Debug)]
pub struct IdentityConfig {
    client_id: ClientId,
    client_secret: ClientSecret,
    tenant_id: String,
}

impl IdentityConfig {
    pub fn new(
        client_id: &str,
        client_secret: &str,
        tenant_id: &str,
    ) -> Result<IdentityConfig, Error> {
        Ok(IdentityConfig {
            client_id: ClientId::new(client_id.to_string()),
            client_secret: ClientSecret::new(client_secret.to_string()),
            tenant_id: tenant_id.to_string(),
        })
    }
}

const AUTH_HEADER: &str = "Authorization";

pub(crate) trait BearerAuthExt {
    fn set_auth(self, value: &str) -> Self;
}

impl Client {
    pub(crate) fn bearer_auth(&self) -> String {
        // safe to unwrap cause is should be called after a refresh which sets
        // `access_token`
        format!(
            "Bearer {}",
            self.access_token.as_ref().unwrap().access_token.secret()
        )
    }

    /// Initialize or refresh access token
    pub(crate) fn refresh_token_access(&mut self) -> Result<(), Error> {
        // Token still valid
        if let Some(token) = &self.access_token {
            if token.expires_on < chrono::Utc::now() {
                return Ok(());
            }
        }

        let IdentityConfig {
            client_id,
            client_secret,
            tenant_id,
        } = &self.identity_config;

        let url = url::Url::parse(&format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        ))?;

        let res = self
            .agent
            .post(&url.to_string())
            .send_form(&[
                ("client_id", client_id.as_str()),
                ("scope", &self.auth_scope),
                ("client_secret", client_secret.secret()),
                ("grant_type", "client_credentials"),
            ])?
            .into_json::<TokenResponse>()?;

        self.access_token = Some(Token {
            expires_on: chrono::Utc::now() + Duration::seconds(res.expires_in as i64),
            access_token: res.access_token,
        });
        Ok(())
    }
}

impl BearerAuthExt for Request {
    fn set_auth(self, value: &str) -> Self {
        self.set(AUTH_HEADER, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::tests::get_env;

    #[test]
    fn test_get_access_token() {
        let env = get_env();
        let config = IdentityConfig::new(env.client_id, env.client_secret, env.tenant_id).unwrap();

        let mut client = Client::new("https://vault-test-sign.vault.azure.net/", config).unwrap();
        client.refresh_token_access().unwrap();
        assert!(client.access_token.is_some());
    }
}
