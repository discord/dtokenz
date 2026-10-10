use crate::application_default_credentials::{
    ApplicationDefaultCredentials, ExternalAccountDetails,
};
use crate::oauth_config::OAuthConfig;
use crate::token_source::{
    AccessTokenError, IdTokenError, Token, TokenSource, fetch_raw_token_from_google_sdk,
};
use google_cloud_auth::credentials::Credentials;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Environment variable naming the service account that ID tokens are minted as when the
/// external account credential file has no `service_account_impersonation_url`.
///
/// The federated principal must hold `roles/iam.serviceAccountOpenIdTokenCreator` on it. Access
/// tokens are unaffected: they stay the federated principal's own.
pub const ID_TOKEN_SERVICE_ACCOUNT_ENV: &str = "DTOKENZ_ID_TOKEN_SERVICE_ACCOUNT";

const IAM_CREDENTIALS_URL: &str = "https://iamcredentials.googleapis.com";
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// If Google's tokeninfo endpoint will not describe a federated access token, assume this much
/// validity. STS issues one-hour tokens and the Google SDK refreshes them well before expiry, so
/// a token it hands us has at least this long left.
const FALLBACK_ACCESS_TOKEN_VALIDITY: chrono::Duration = chrono::Duration::minutes(30);

pub struct ExternalAccountInner {
    /// Credentials for access tokens. If the file has `service_account_impersonation_url`, these
    /// impersonate; otherwise they are the federated principal.
    credentials: Credentials,
    /// Always the federated principal, used to call `generateIdToken`.
    federated_credentials: Credentials,
    scopes: Vec<String>,
}

/// A token source for an [external account] credential file, i.e. Workload Identity Federation.
///
/// Access tokens come from the Security Token Service via the Google SDK, exactly as for gcloud,
/// Go or Python. ID tokens need one extra step, because Google only signs ID tokens for users and
/// service accounts, never for a federated principal: dtokenz calls `generateIdToken` on a service
/// account using the federated access token. The account is
///
/// 1. the one in `service_account_impersonation_url`, if the file has it (then the Google SDK
///    impersonates it for access tokens too), otherwise
/// 2. the one named by [`ID_TOKEN_SERVICE_ACCOUNT_ENV`].
///
/// Either way the federated principal needs `roles/iam.serviceAccountOpenIdTokenCreator` on that
/// account. With neither configured, [`TokenSource::get_id_token`] fails with an error saying so.
///
/// [external account]: https://google.aip.dev/auth/4117
pub struct ExternalAccount {
    oauth_config: OAuthConfig,
    adc: ExternalAccountDetails,
    id_token_service_account: Option<String>,
    inner: Arc<RwLock<ExternalAccountInner>>,
}

impl ExternalAccount {
    /// Attempt to instantiate a client for an external account credential file.
    ///
    /// This looks at either GOOGLE_APPLICATION_CREDENTIALS or the default ADC json path for an
    /// `external_account` document. If none is found, `Ok(None)` is returned.
    pub async fn new(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
    ) -> anyhow::Result<Option<Self>> {
        let adc = match ApplicationDefaultCredentials::load_from_file(None)? {
            Some((ApplicationDefaultCredentials::ExternalAccount(adc), _)) => adc,
            _ => return Ok(None),
        };
        let scopes: Vec<_> = scopes.iter().map(|s| s.as_ref().to_string()).collect();
        let id_token_service_account = adc.impersonated_service_account().or_else(|| {
            std::env::var(ID_TOKEN_SERVICE_ACCOUNT_ENV)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        });
        let (credentials, federated_credentials) = Self::build_credentials(&adc, &scopes)?;
        Ok(Some(Self {
            oauth_config: oauth_config.clone(),
            adc,
            id_token_service_account,
            inner: Arc::new(RwLock::new(ExternalAccountInner {
                credentials,
                federated_credentials,
                scopes,
            })),
        }))
    }

    fn build_credentials(
        adc: &ExternalAccountDetails,
        scopes: &[String],
    ) -> anyhow::Result<(Credentials, Credentials)> {
        let credentials =
            google_cloud_auth::credentials::external_account::Builder::new(adc.to_json())
                .with_scopes(scopes.iter().cloned())
                .build()?;
        let federated_credentials = google_cloud_auth::credentials::external_account::Builder::new(
            adc.to_json_without_impersonation(),
        )
        .with_scopes([CLOUD_PLATFORM_SCOPE])
        .build()?;
        Ok((credentials, federated_credentials))
    }

    /// The service account ID tokens are minted as, if one is configured.
    pub fn id_token_service_account(&self) -> Option<&str> {
        self.id_token_service_account.as_deref()
    }
}

impl Debug for ExternalAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExternalAccount(client_id={}, audience={}, id_token_service_account={:?}, inner=...)",
            self.oauth_config.web.client_id, self.adc.audience, self.id_token_service_account
        )
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateIdTokenRequest<'a> {
    audience: &'a str,
    include_email: bool,
}

#[derive(serde::Deserialize)]
struct GenerateIdTokenResponse {
    token: String,
}

#[derive(serde::Deserialize)]
struct GoogleApiErrorBody {
    error: GoogleApiError,
}

#[derive(serde::Deserialize)]
struct GoogleApiError {
    code: u16,
    message: String,
    #[serde(default)]
    status: String,
}

/// Call `iamcredentials.generateIdToken` on `service_account` as the holder of `bearer`.
///
/// Returns the raw JWT. `base_url` is the IAM Credentials API root; it is a parameter so tests
/// can point it at a local server.
async fn generate_id_token(
    base_url: &str,
    service_account: &str,
    audience: &str,
    bearer: &str,
) -> Result<String, IdTokenError> {
    let url = format!("{base_url}/v1/projects/-/serviceAccounts/{service_account}:generateIdToken");
    tracing::debug!("Requesting ID token for {service_account} with audience {audience}");
    let response = reqwest::Client::new()
        .post(&url)
        .bearer_auth(bearer)
        .json(&GenerateIdTokenRequest {
            audience,
            include_email: true,
        })
        .send()
        .await
        .map_err(IdTokenError::TokenServiceError)?;
    let status = response.status();
    if status.is_success() {
        return response
            .json::<GenerateIdTokenResponse>()
            .await
            .map(|r| r.token)
            .map_err(IdTokenError::InvalidResponseData);
    }
    let detail = match response.json::<GoogleApiErrorBody>().await {
        Ok(body) => format!(
            "{} {}: {}",
            body.error.code, body.error.status, body.error.message
        ),
        Err(_) => status.to_string(),
    };
    let hint = if status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::UNAUTHORIZED
    {
        format!(
            " (the federated principal needs roles/iam.serviceAccountOpenIdTokenCreator on {service_account})"
        )
    } else {
        String::new()
    };
    Err(IdTokenError::Anyhow(anyhow::anyhow!(
        "generateIdToken on {service_account} failed: {detail}{hint}"
    )))
}

#[async_trait::async_trait]
impl TokenSource for ExternalAccount {
    fn kind(&self) -> &'static str {
        "external account"
    }

    async fn credentials(&self) -> Credentials {
        self.inner.read().await.credentials.clone()
    }

    async fn refresh(&self) -> anyhow::Result<()> {
        let mut writer = self.inner.write().await;
        let (credentials, federated_credentials) =
            Self::build_credentials(&self.adc, &writer.scopes)?;
        *writer = ExternalAccountInner {
            credentials,
            federated_credentials,
            scopes: writer.scopes.clone(),
        };
        Ok(())
    }

    async fn get_access_token_impl(&self) -> Result<Token, AccessTokenError> {
        let token = fetch_raw_token_from_google_sdk(self.credentials().await).await?;
        match Token::from_access_token(token.clone()).await {
            Ok(t) => Ok(t),
            Err(e) => {
                // tokeninfo describes impersonated and user tokens, but may decline a federated
                // STS token. The token is still perfectly usable; only its expiry is unknown.
                tracing::debug!(
                    "tokeninfo did not describe the federated access token ({e}); assuming {} of validity",
                    FALLBACK_ACCESS_TOKEN_VALIDITY
                );
                Ok(Token {
                    token,
                    expires_at: chrono::Utc::now() + FALLBACK_ACCESS_TOKEN_VALIDITY,
                })
            }
        }
    }

    async fn get_id_token_impl(&self) -> Result<Token, IdTokenError> {
        let Some(service_account) = self.id_token_service_account.as_deref() else {
            return Err(IdTokenError::Anyhow(anyhow::anyhow!(
                "Google does not issue ID tokens for federated principals. Set {ID_TOKEN_SERVICE_ACCOUNT_ENV} \
                 to a service account the principal may call generateIdToken on, or add \
                 service_account_impersonation_url to the credential file"
            )));
        };
        let federated = self.inner.read().await.federated_credentials.clone();
        let bearer = fetch_raw_token_from_google_sdk(federated)
            .await
            .map_err(|e| {
                IdTokenError::Anyhow(
                    anyhow::anyhow!(e)
                        .context("fetching a federated access token to call generateIdToken with"),
                )
            })?;
        let jwt = generate_id_token(
            IAM_CREDENTIALS_URL,
            service_account,
            &self.oauth_config.web.client_id,
            &bearer,
        )
        .await?;
        Ok(Token::from_id_token(jwt).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::extract::Path;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;

    const SA: &str = "buildkite-idtoken@discord-tools-prd.iam.gserviceaccount.com";

    async fn handler(
        Path(account): Path<String>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        // axum keeps the `:generateIdToken` suffix in the path segment.
        assert_eq!(account, format!("{SA}:generateIdToken"));
        assert_eq!(body["audience"], "client-id");
        assert_eq!(body["includeEmail"], true);
        match headers.get("authorization").and_then(|h| h.to_str().ok()) {
            Some("Bearer federated-token") => (
                StatusCode::OK,
                Json(serde_json::json!({ "token": "signed.id.token" })),
            ),
            _ => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": {
                        "code": 403,
                        "message": "Permission 'iam.serviceAccounts.getOpenIdToken' denied",
                        "status": "PERMISSION_DENIED"
                    }
                })),
            ),
        }
    }

    fn server() -> anyhow::Result<axum_test::TestServer> {
        let app =
            axum::Router::new().route("/v1/projects/-/serviceAccounts/{account}", post(handler));
        axum_test::TestServer::builder().http_transport().build(app)
    }

    fn base_url(server: &axum_test::TestServer) -> anyhow::Result<String> {
        Ok(server
            .server_address()
            .ok_or_else(|| anyhow::anyhow!("test server has no address"))?
            .to_string()
            .trim_end_matches('/')
            .to_string())
    }

    #[tokio::test]
    async fn generate_id_token_returns_the_jwt() -> anyhow::Result<()> {
        let server = server()?;
        let jwt =
            generate_id_token(&base_url(&server)?, SA, "client-id", "federated-token").await?;
        assert_eq!(jwt, "signed.id.token");
        Ok(())
    }

    #[tokio::test]
    async fn generate_id_token_explains_permission_denied() -> anyhow::Result<()> {
        let server = server()?;
        let err = match generate_id_token(&base_url(&server)?, SA, "client-id", "wrong").await {
            Ok(_) => anyhow::bail!("expected an error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("403 PERMISSION_DENIED"), "{err}");
        assert!(err.contains("serviceAccountOpenIdTokenCreator"), "{err}");
        assert!(err.contains(SA), "{err}");
        Ok(())
    }
}
