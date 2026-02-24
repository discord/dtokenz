use crate::oauth_config::OAuthConfig;
use crate::token_source::{IdTokenError, TokenSource};
use google_cloud_auth::credentials::Credentials;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub struct MetadataServiceInner {
    credentials: Credentials,
    scopes: Vec<String>,
}

/// A client that talks to the Google metadata service and gets tokens for the default service account.
///
/// This only will work on hosts that are within the GCP network.
///
/// See [`google_cloud_auth::credentials::mds`] for more details.
pub struct MetadataService {
    oauth_config: OAuthConfig,
    inner: Arc<RwLock<MetadataServiceInner>>,
}

impl MetadataService {
    /// Verify whether the metadata.google.internal endpoint exists, and it returns a 2XX.
    pub async fn metadata_endpoint_exists() -> anyhow::Result<bool> {
        // Quick sanity check to see if we're even going to be able to hit the internal endpoint
        tracing::debug!("Verifying metadata service exists at metadata.google.internal");
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(100))
            .build()?;
        let res = client.get("http://metadata.google.internal").send().await;
        match res {
            Ok(r) => {
                if r.error_for_status().is_ok() {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Attempt to create an auth client that will contact the metadata service if possible.
    ///
    /// To verify that the metadata service is available, see [`Self::metadata_endpoint_exists`]
    pub async fn new(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
    ) -> anyhow::Result<MetadataService> {
        let scopes = scopes.iter().map(|s| s.as_ref().to_string()).collect();
        let credentials = google_cloud_auth::credentials::mds::Builder::default()
            .with_scopes(&scopes)
            .build()?;
        Ok(Self {
            oauth_config: oauth_config.clone(),
            inner: Arc::new(RwLock::new(MetadataServiceInner {
                credentials,
                scopes,
            })),
        })
    }
}

impl Debug for MetadataService {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MetadataService(client_id={}, inner=...)",
            self.oauth_config.web.client_id
        )
    }
}

#[async_trait::async_trait]
impl TokenSource for MetadataService {
    fn kind(&self) -> &'static str {
        "metadata service account"
    }

    async fn credentials(&self) -> Credentials {
        self.inner.read().await.credentials.clone()
    }

    async fn refresh(&self) -> anyhow::Result<()> {
        let mut writer = self.inner.write().await;
        let new_creds = google_cloud_auth::credentials::mds::Builder::default()
            .with_scopes(&writer.scopes)
            .build()?;
        *writer = MetadataServiceInner {
            credentials: new_creds,
            scopes: writer.scopes.clone(),
        };
        Ok(())
    }

    async fn get_id_token_impl(&self) -> Result<crate::token_source::Token, IdTokenError> {
        let url = reqwest::Url::parse_with_params(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
            &[("audience", self.oauth_config.web.client_id.as_str()), ("format", "full")]).map_err(|e| IdTokenError::Anyhow(e.into())
        )?;
        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .header("metadata-flavor", "Google")
            .send()
            .await
            .map_err(IdTokenError::TokenServiceError)?
            .error_for_status()
            .map_err(IdTokenError::TokenServiceError)?;
        let text = response
            .text()
            .await
            .map_err(IdTokenError::InvalidResponseData)?;
        // Google just sends this JWT back raw, not in json or anything
        Ok(crate::token_source::Token::from_id_token(text).await?)
    }
}
