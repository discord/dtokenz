use crate::application_default_credentials::{
    ApplicationDefaultCredentials, ServiceAccountDetails,
};
use crate::oauth_config::OAuthConfig;
use crate::token_source::{ClaimsRef, IdTokenError, TokenSource, fetch_id_token_from_google};
use google_cloud_auth::credentials::Credentials;
use google_cloud_auth::credentials::service_account::AccessSpecifier;
use jsonwebtoken::EncodingKey;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ServiceAccountInner {
    credentials: Credentials,
    scopes: Vec<String>,
}

/// A token source for a service account that is authenticated by a key
///
/// See [`google_cloud_auth::credentials::service_account`] for more details.
pub struct ServiceAccount {
    oauth_config: OAuthConfig,
    adc: ServiceAccountDetails,
    jwt_key: EncodingKey,
    inner: Arc<RwLock<ServiceAccountInner>>,
}

impl ServiceAccount {
    /// Attempt to instantiate a client for a service account that has a key
    ///
    /// This will look at either GOOGLE_APPLICATION_CREDENTIALS, or the default ADC json path
    /// looking for a service_account configuration. If none is found, `Ok(None)` will be returned.
    pub async fn new(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
    ) -> anyhow::Result<Option<Self>> {
        let scopes: Vec<_> = scopes.iter().map(|s| s.as_ref().to_string()).collect();
        let maybe_adc = ApplicationDefaultCredentials::load_from_file(None)?;
        let adc = match maybe_adc {
            None => return Ok(None),
            Some((ApplicationDefaultCredentials::AuthorizedUser(_), _)) => return Ok(None),
            Some((ApplicationDefaultCredentials::ServiceAccount(sa), _)) => sa,
        };
        let jwt_key = jsonwebtoken::EncodingKey::from_rsa_pem(adc.private_key.as_bytes())?;

        let creds = Self::get_creds_for_access_token(&adc, scopes.clone())?;
        Ok(Some(Self {
            oauth_config: oauth_config.clone(),
            adc,
            jwt_key,
            inner: Arc::new(RwLock::new(ServiceAccountInner {
                credentials: creds,
                scopes,
            })),
        }))
    }

    /// Build the credentials object required to get an access token.
    fn get_creds_for_access_token(
        adc: &ServiceAccountDetails,
        scopes: Vec<String>,
    ) -> anyhow::Result<Credentials> {
        let service_account_key = serde_json::to_value(adc)?;
        let specifier = AccessSpecifier::from_scopes(scopes);
        Ok(
            google_cloud_auth::credentials::service_account::Builder::new(service_account_key)
                .with_access_specifier(specifier)
                .build()?,
        )
    }
}

impl Debug for ServiceAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ServiceAccount(client_id={}, inner=...)",
            self.oauth_config.web.client_id
        )
    }
}

#[async_trait::async_trait]
impl TokenSource for ServiceAccount {
    fn kind(&self) -> &'static str {
        "service account"
    }

    async fn credentials(&self) -> Credentials {
        self.inner.read().await.credentials.clone()
    }

    async fn refresh(&self) -> anyhow::Result<()> {
        let mut writer = self.inner.write().await;
        let credentials = Self::get_creds_for_access_token(&self.adc, writer.scopes.clone())?;
        *writer = ServiceAccountInner {
            credentials,
            scopes: writer.scopes.clone(),
        };
        Ok(())
    }

    async fn get_id_token_impl(&self) -> Result<crate::token_source::Token, IdTokenError> {
        // For this account type, this is a self-signed JWT that we can then exchange for
        // one signed from google.
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = ClaimsRef {
            iss: &self.adc.client_email,
            sub: &self.adc.client_email,
            scope: None,
            aud: Some(&self.oauth_config.web.token_uri),
            exp: now + 3600,
            iat: now,
            target_audience: Some(&self.oauth_config.web.client_id),
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &self.jwt_key)
            .map_err(|e| IdTokenError::Anyhow(e.into()))?;

        fetch_id_token_from_google(
            &self.oauth_config.web.token_uri,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &token),
            ],
        )
        .await
    }
}
