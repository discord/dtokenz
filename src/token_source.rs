use crate::authorized_user::{AuthorizedUser, OAuthCallback};
use crate::metadata_service::MetadataService;
use crate::oauth_config::OAuthConfig;
use crate::service_account::ServiceAccount;
use anyhow::Context;
use base64::Engine;
use google_cloud_auth::credentials::{CacheableResource, Credentials};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::IntoUrl;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;

/// The claims that google returns in their JWTs
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub scope: Option<String>,
    pub aud: Option<String>,
    pub exp: u64,
    pub iat: u64,
    /// Only used when requesting an ID token for e.g. a service account.
    #[serde(default)]
    pub target_audience: Option<String>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ClaimsRef<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub scope: Option<&'a str>,
    pub aud: Option<&'a str>,
    pub exp: u64,
    pub iat: u64,
    /// Only used when requesting an ID token for e.g. a service account.
    #[serde(default)]
    pub target_audience: Option<&'a str>,
}

/// Validate and decode the payload from ID tokens that google returns.
///
/// Note that this reaches out to google to fetch the current JWKs, so there is
/// network traffic involved.
async fn decode_id_token(data: &str) -> anyhow::Result<Claims> {
    const JWK_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

    fn decode_jwt(data: &str, jwk: &Jwk) -> anyhow::Result<Claims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        Ok(jsonwebtoken::decode(data, &DecodingKey::from_jwk(jwk)?, &validation)?.claims)
    }

    // https://developers.google.com/identity/openid-connect/openid-connect#discovery
    let jwks = reqwest::get(JWK_URL)
        .await
        .with_context(|| format!("Fetching JWKs from {JWK_URL}"))?
        .json::<JwkSet>()
        .await
        .with_context(|| format!("Decoding JWKs from {JWK_URL}"))?;

    jwks.keys
        .into_iter()
        .find_map(|jwk| match decode_jwt(data, &jwk) {
            Ok(claims) => Some(claims),
            Err(e) => {
                tracing::debug!("Error decoding with JWK: {}", e);
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("ID token returned was not signed with any valid JWKs"))
}

#[derive(Debug, thiserror::Error)]
pub enum AccessTokenError {
    #[error("Credentials appear to be expired")]
    RefreshTokenExpired(#[source] google_cloud_auth::errors::CredentialsError),
    #[error(transparent)]
    GoogleAuthError(google_cloud_auth::errors::CredentialsError),
    #[error("Received Not Modified from the Google SDK, but an etag was not sent")]
    InvalidNotModified,
    #[error("No authorization header was returned from the Google SDK")]
    NoAuthorizationHeader,
    #[error("Google SDK returned a non-Bearer authorization header")]
    NonBearerHeader,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GoogleOAuthErrorResponse {
    pub error: String,
    pub error_description: String,
}

#[derive(Debug, thiserror::Error)]
pub enum IdTokenError {
    #[error("Credentials appear to be expired")]
    RefreshTokenExpired,
    #[error("No refresh token was found for this account")]
    MissingRefreshToken,
    #[error(transparent)]
    TokenServiceError(reqwest::Error),
    #[error("Error returned from google: {} {}", .0.error, .0.error_description)]
    OAuthError(GoogleOAuthErrorResponse),
    #[error("Invalid data returned from token service: {}", .0)]
    InvalidResponseData(reqwest::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Try to parse out the information from the Google SDK into something more standard
///
/// This may need to change over time if the values returned from the sdk change substantially
pub async fn fetch_token_from_google_sdk(
    credentials: Credentials,
) -> Result<Token, AccessTokenError> {
    match credentials.headers(Default::default()).await {
        Ok(headers) => match headers {
            CacheableResource::NotModified => Err(AccessTokenError::InvalidNotModified),
            CacheableResource::New { data, .. } => {
                let token = data
                    .get("authorization")
                    .ok_or(AccessTokenError::NoAuthorizationHeader)?
                    .to_str()
                    .map_err(|_| AccessTokenError::NoAuthorizationHeader)?
                    .strip_prefix("Bearer ")
                    .ok_or(AccessTokenError::NonBearerHeader)?
                    .to_string();
                Ok(Token::from_access_token(token).await?)
            }
        },
        // We can't access the message directly, and the display impl for CredentialsError
        // doesn't give us the most helpful message. For now, assume we're not logged in
        // if the error isn't transient.
        Err(e) if !e.is_transient() => Err(AccessTokenError::RefreshTokenExpired(e)),
        Err(e) => Err(AccessTokenError::GoogleAuthError(e)),
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct IdTokenResponse {
    id_token: String,
}

/// Reach out to Google directly to try to fetch an ID token
///
/// The URI comes from the oauth configuration, and the body has to be something that
/// serializes usefully to json. The contents vary based on the type of account you are
/// trying to authenticate. We then parse the returned objects out to something more structured.
pub async fn fetch_id_token_from_google<T: serde::Serialize>(
    token_uri: impl IntoUrl,
    body: &T,
) -> Result<Token, IdTokenError> {
    tracing::debug!("Attempting to fetch new ID token from google");
    let client = reqwest::Client::new();
    let response = client
        .post(token_uri)
        .form(&body)
        .send()
        .await
        .map_err(IdTokenError::TokenServiceError)?;
    if response.status().is_success() {
        tracing::debug!("Successfully fetched new ID token from google; decoding now");
        let token_string = response
            .json::<IdTokenResponse>()
            .await
            .map(|r| r.id_token)
            .map_err(IdTokenError::InvalidResponseData)?;
        let token = Token::from_id_token(token_string).await?;
        tracing::debug!("Successfully decoded new ID token from google");
        Ok(token)
    } else {
        let error = match response.json::<GoogleOAuthErrorResponse>().await {
            Ok(error) if error.error == "invalid_grant" => IdTokenError::RefreshTokenExpired,
            Ok(error) => IdTokenError::OAuthError(error),
            Err(e) => IdTokenError::InvalidResponseData(e),
        };
        tracing::debug!("Could not fetch new ID token from google: {}", error);
        Err(error)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
struct TokenInfoResponse {
    exp: String,
}

/// expires. This is used for every account type.The core two pieces of data needed to do authentication. This is generally serialized to disk.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Token {
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl Token {
    fn decode_self_signed_jwt(token: String) -> anyhow::Result<Token> {
        let Some(b64_json) = token.split('.').nth(1) else {
            return Err(anyhow::anyhow!(
                "Could not find encoded JWT claims in token"
            ));
        };
        let decoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(b64_json)?;
        let claims = serde_json::from_slice::<Claims>(&decoded)?;
        let expires_at = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid expiration time in token"))?;
        Ok(Token { token, expires_at })
    }

    /// Given an opaque access token from Google, attempt to parse out and validate useful info
    ///
    /// Note: This method may access the network.
    async fn from_access_token(t: impl Into<String>) -> anyhow::Result<Token> {
        let token = t.into();
        // The ServiceAccount type returns a self-signed JWT from the Google SDK's header() / access
        // token method. The tokeninfo endpoint doesn't like getting this JWT as an access token
        // We check if the token starts with ya29, as that's what both the metadata service on
        // GCP, and on local dev machines return (there is only one dot locally, but two on GCP)
        // If it doesn't start with ya29, we try to decode the data as a JWT so we can get the exp
        // time.
        if !token.starts_with("ya29") {
            return Self::decode_self_signed_jwt(token);
        }

        let token_info: TokenInfoResponse = reqwest::get(format!(
            "https://oauth2.googleapis.com/tokeninfo?access_token={token}"
        ))
        .await?
        .error_for_status()?
        .json()
        .await?;

        let exp = token_info.exp.parse()?;
        let expires_at = chrono::DateTime::from_timestamp(exp, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid expiration time in token"))?;
        Ok(Token { token, expires_at })
    }

    /// Given an opaque access token from Google, attempt to parse out and validate useful info
    ///
    /// Note: This method may access the network
    pub(crate) async fn from_id_token(t: impl Into<String>) -> anyhow::Result<Token> {
        let token = t.into();
        let decoded = decode_id_token(&token).await?;
        let expires_at = chrono::DateTime::from_timestamp(decoded.exp as i64, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid expiration time in token"))?;
        Ok(Token { token, expires_at })
    }
}

#[async_trait::async_trait]
pub trait TokenSource: Send + Sync + std::fmt::Debug {
    /// A human readable description of this class e.g. "authorized user"
    fn kind(&self) -> &'static str;

    /// Return a [`Credentials`] object that other Google Cloud SDK APIs can use
    async fn credentials(&self) -> Credentials;

    /// Attempt to re-authenticate if possible. This may be an interactive action.
    async fn refresh(&self) -> anyhow::Result<()>;

    /// The actual implementation to fetch an ID token. This varies based on client type.
    async fn get_id_token_impl(&self) -> Result<Token, IdTokenError>;

    /// Common implementation for getting an id token, or refreshing and retrying
    /// if the token is expired.
    async fn get_id_token_with_refresh(&self, refresh: bool) -> Result<Token, IdTokenError> {
        tracing::debug!("Getting id token for {} token source", self.kind());
        match self.get_id_token_impl().await {
            Err(IdTokenError::RefreshTokenExpired) if refresh => {
                tracing::debug!("Refresh token was expired. Attempting to renew");
                self.refresh().await?;
                tracing::debug!("Attempting to fetch id token after refreshing");
                self.get_id_token_with_refresh(false).await
            }
            res => res,
        }
    }

    /// Get an [id token](https://cloud.google.com/docs/authentication/token-types#id)
    ///
    /// If the id token that the implementation fetches is expired, a refresh is automatically
    /// attempted.
    ///
    /// Note that this method necessarily can perform network operations.
    async fn get_id_token(&self) -> Result<Token, IdTokenError> {
        self.get_id_token_with_refresh(true).await
    }

    /// The actual implementation to fetch an access token.
    ///
    /// By default, this just uses the headers() method from credentials to fetch an access token
    async fn get_access_token_impl(&self) -> Result<Token, AccessTokenError> {
        fetch_token_from_google_sdk(self.credentials().await).await
    }

    /// Common implementation for getting an access token, or refreshing and retrying
    /// if the token is expired.
    async fn get_access_token_with_refresh(
        &self,
        refresh: bool,
    ) -> Result<Token, AccessTokenError> {
        tracing::debug!("Getting access token for {} token source", self.kind());
        match self.get_access_token_impl().await {
            Err(AccessTokenError::RefreshTokenExpired(e)) if refresh => {
                tracing::debug!(
                    "Refresh token was expired. Attempting to renew. (Error: {})",
                    e
                );
                self.refresh().await?;
                tracing::debug!("Attempting to fetch access token after refreshing");
                self.get_access_token_with_refresh(false).await
            }
            res => res,
        }
    }

    /// Get an [access token](https://cloud.google.com/docs/authentication/token-types#access), refreshing if necessary
    async fn get_access_token(&self) -> Result<Token, AccessTokenError> {
        self.get_access_token_with_refresh(true).await
    }
}

/// Attempt to auto-detect what type of account to use, and return an appropriate [`TokenSource`]
///
/// For convenience, there is also a singleton version of the returned value of this method
/// available at [`auto_detect_singleton()`]
///
/// This method attempts to fetch a token based on the environment in the least interactive way
/// possible.
///
/// If you need a specific type of account, or want to preference one over the other,
/// use the specific clients' `new()` methods.
///
/// tl;dr; This is the preference order of token sources if they exist:
/// - Non-expired Authorized User credentials
/// - Service account application default credentials
/// - Metadata service
/// - Authorized User credentials, created / refreshed potentially interactively.
///
/// The more detailed heuristic is:
/// - Attempt to load authorized user credentials from disk. If they are present and NOT EXPIRED
///   then return that authorized user.
/// - Attempt to load service account json from GOOGLE_APPLICATION_CREDENTIALS or
///   application_default_credentials.json (in ~/.config/gcloud/application_default_credentials.json).
///   If the json file exists and has the right account type in it, then a service account client
///   will be returned.
/// - If GOOGLE_APPLICATION_CREDENTIALS is not set, attempt to see if there is a metadata
///   service, and use that if possible. This will prefer service accounts on e.g. GCP hosts,
///   so if a specific authorized user account is needed, do not use this method.
/// - If after all of that, we still don't have a client, attempt to get an authorized user
///   client. If `interactive` is true, then if no credentials are already configured, the
///   web flow will be initialized. If `interactive` is false, an error will be returned.
///   See [`AuthorizedUser`] for more details about how interactive authentication works.
///
/// # Arguments
///
/// oauth_config: The oauth application to authenticate against
/// scopes: A list of scopes to request when fetching tokens
/// interactive: If true, use the web flow if no other non-interactive token sources could be found
/// interactive_auth_message: The message to print to users' consoles if interactive authentication
///                           is required. The string `%url%` is replaced with the URL that
///                           will be opened in a web browser. This is used to try to remove
///                           the surprise when a browser pops up for users.
pub async fn auto_detect(
    oauth_config: OAuthConfig,
    scopes: &[impl AsRef<str>],
    interactive: bool,
    interactive_auth_message: impl AsRef<str>,
) -> anyhow::Result<Box<dyn TokenSource + Send + Sync>> {
    auto_detect_with_callback(
        oauth_config,
        scopes,
        interactive,
        interactive_auth_message,
        crate::authorized_user::handle_oauth_callback,
    )
    .await
}

/// Like [`auto_detect`], but specify the HTTP callback to use after a successful authorization.
///
/// Users should prefer [`auto_detect`] / [`auto_detect_singleton`], unless a custom
/// post-authentication page is desired.
///
/// The oauth_response_callback is generally just a function that takes no parameters, and
/// returns a string, or something that can be converted into a [`axum::response::Response`].
pub async fn auto_detect_with_callback(
    oauth_config: OAuthConfig,
    scopes: &[impl AsRef<str>],
    interactive: bool,
    interactive_auth_message: impl AsRef<str>,
    oauth_response_callback: impl Into<OAuthCallback>,
) -> anyhow::Result<Box<dyn TokenSource + Send + Sync>> {
    let interactive_auth_message = interactive_auth_message.as_ref();
    let oauth_response_callback = oauth_response_callback.into();
    if let Some(client) = AuthorizedUser::new_unexpired_from_disk_with_callback(
        &oauth_config,
        scopes,
        interactive_auth_message,
        oauth_response_callback.clone(),
    )
    .await?
    {
        return Ok(Box::new(client));
    }

    if let Some(client) = ServiceAccount::new(&oauth_config, scopes).await? {
        return Ok(Box::new(client));
    }

    if std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_err()
        && MetadataService::metadata_endpoint_exists().await?
    {
        return Ok(Box::new(MetadataService::new(&oauth_config, scopes).await?));
    }

    let client = AuthorizedUser::new_with_callback(
        &oauth_config,
        scopes,
        interactive,
        interactive_auth_message,
        oauth_response_callback,
    )
    .await?;
    Ok(Box::new(client))
}

pub type SingletonClient = Arc<Box<dyn TokenSource>>;

/// Get a single instance of an auto-detected client.
///
/// One client is maintained for the lifetime of the program per oauth client id,
/// scopes list, and "interactive" tuple.
///
/// If instantiating the client fails, subsequent calls will attempt to instantiate again.
/// Once instantiating, a single instance is shared.
pub async fn auto_detect_singleton(
    oauth_config: OAuthConfig,
    scopes: &[impl AsRef<str>],
    interactive: bool,
    interactive_auth_message: impl AsRef<str>,
) -> anyhow::Result<SingletonClient> {
    use itertools::Itertools;

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    struct SingletonKey(String, String, bool);
    let key = SingletonKey(
        oauth_config.web.client_id.clone(),
        scopes.iter().map(|s| s.as_ref()).sorted().join(" "),
        interactive,
    );
    static SINGLETON_MAP: LazyLock<RwLock<HashMap<SingletonKey, SingletonClient>>> =
        LazyLock::new(Default::default);
    {
        if let Some(c) = SINGLETON_MAP.read().await.get(&key) {
            return Ok(c.clone());
        }
    }
    let mut writer = SINGLETON_MAP.write().await;
    match writer.entry(key) {
        Entry::Occupied(e) => Ok(e.get().clone()),
        Entry::Vacant(e) => Ok(e
            .insert(Arc::new(
                auto_detect(oauth_config, scopes, interactive, interactive_auth_message).await?,
            ))
            .clone()),
    }
}
