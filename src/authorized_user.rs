use crate::application_default_credentials::{
    ApplicationDefaultCredentials, AuthorizedUserDetails,
};
use crate::oauth_config::OAuthConfig;
use crate::state::PersistedState;
use crate::token_source::{
    AccessTokenError, GoogleOAuthErrorResponse, IdTokenError, TokenSource,
    fetch_id_token_from_google, fetch_token_from_google_sdk,
};
use anyhow::{Context, anyhow};
use axum::Router;
use axum::extract::Query;
use axum::http::Response;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use base64::Engine;
use futures::future::BoxFuture;
use futures::{FutureExt, TryFutureExt};
use google_cloud_auth::credentials::Credentials;
use itertools::Itertools;
use rand::Rng;
use sha2::Digest;
use std::fmt::{Debug, Formatter};
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use url::Url;

/// Used to communicate the oauth code back to the axum webserver.
type OAuthCallbackState =
    Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<Result<String, CallbackError>>>>>;

/// The response that comes back from google after the user has gone through the authorization flow
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct LoginResponse {
    access_token: String,
    expires_in: u64,
    id_token: String,
    refresh_token: String,
    scope: String,
    token_type: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct IdTokenRequest {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    // Must only be "refresh_token"
    grant_type: String,
}

struct AuthorizedUserState {
    credentials: Credentials,
    state: PersistedState,
}

pub enum AuthorizedUserLoadSource {
    StateFile,
    ADCJson,
    WebAuthFlow,
}

#[derive(Clone)]
pub struct OAuthCallback {
    callback:
        Arc<dyn 'static + Send + Sync + Fn() -> BoxFuture<'static, Response<axum::body::Body>>>,
}

impl OAuthCallback {
    fn call(&self) -> BoxFuture<'static, Response<axum::body::Body>> {
        (self.callback)()
    }
}

impl<R, Fut, F> From<F> for OAuthCallback
where
    R: IntoResponse,
    Fut: Future<Output = R> + Send + 'static,
    F: Fn() -> Fut + Send + Sync + 'static,
{
    fn from(value: F) -> OAuthCallback {
        OAuthCallback {
            callback: Arc::new(move || value().map(|b| b.into_response()).boxed()),
        }
    }
}

/// A token source for [Authorized User Accounts](https://docs.cloud.google.com/docs/authentication/token-types#user-access-tokens)
///
/// This requires a user to actively log in in a browser.
///
/// See [`google_cloud_auth::credentials::user_account`] for more details.
pub struct AuthorizedUser {
    load_source: AuthorizedUserLoadSource,
    persist_on_fetch: bool,
    oauth_config: OAuthConfig,
    // If non-empty, this message will be printed to stderr immediately before
    // initiating a web-based oauth flow. The literal sequence '%url%' will be
    // replaced with the URL to be opened.
    interactive_auth_message: String,
    inner: Arc<RwLock<AuthorizedUserState>>,
    callback: OAuthCallback,
}

impl Debug for AuthorizedUser {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuthorizedUser(client_id={}, inner=...)",
            self.oauth_config.web.client_id
        )
    }
}

impl AuthorizedUser {
    fn load_source(&self) -> &'static str {
        match self.load_source {
            AuthorizedUserLoadSource::StateFile => "state file",
            AuthorizedUserLoadSource::ADCJson => "adc json file",
            AuthorizedUserLoadSource::WebAuthFlow => "web auth flow",
        }
    }

    /// Get the new ADC based on the current config. This is fed into the google SDK library
    fn adc(
        oauth_config: &OAuthConfig,
        refresh_token: impl Into<String>,
    ) -> ApplicationDefaultCredentials {
        ApplicationDefaultCredentials::AuthorizedUser(AuthorizedUserDetails {
            client_id: oauth_config.web.client_id.clone(),
            client_secret: oauth_config.web.client_secret.clone(),
            refresh_token: refresh_token.into(),
            token_uri: Some(oauth_config.web.token_uri.clone()),
            quota_project_id: None,
        })
    }

    /// Create a new client from an [`application_default_credentials.json`] file.
    async fn create_credentials(state: &PersistedState) -> anyhow::Result<Credentials> {
        let authorized_user = serde_json::to_value(&state.adc)?;

        let credentials =
            google_cloud_auth::credentials::user_account::Builder::new(authorized_user)
                .with_scopes(&state.scopes)
                .build()?;
        Ok(credentials)
    }

    /// Create a new client by having the user follow the web auth flow
    ///
    /// This method is blocking on user input, and will write to both the network and disk.
    async fn new_from_web(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
        persist_on_fetch: bool,
        interactive_auth_message: impl AsRef<str>,
        oauth_callback_handler: OAuthCallback,
    ) -> anyhow::Result<AuthorizedUserState> {
        let response = Self::web_flow(
            oauth_config,
            scopes,
            interactive_auth_message,
            oauth_callback_handler,
        )
        .await?;
        let login_response_text = response.text().await?;
        let login_response: LoginResponse = match serde_json::from_str(&login_response_text) {
            Ok(login_response) => Ok(login_response),
            Err(e) => {
                match serde_json::from_str::<GoogleOAuthErrorResponse>(&login_response_text) {
                    Ok(details) => Err(anyhow::anyhow!(
                        "Error returned from google: {} {}",
                        details.error,
                        details.error_description
                    )),
                    Err(_) => {
                        tracing::debug!("Auth response body: {}", login_response_text);
                        Err(e).context("See debug logs for message body")
                    }
                }
            }
        }?;

        let new_adc = Self::adc(oauth_config, &login_response.refresh_token);

        let id_token = crate::token_source::Token::from_id_token(login_response.id_token).await?;
        let state = PersistedState::new(oauth_config, scopes.iter().map(AsRef::as_ref), new_adc)
            .with_id_token(id_token)
            .await?;
        if persist_on_fetch {
            state.persist()?;
        }

        let authorized_user = serde_json::to_value(&state.adc)?;

        let credentials =
            google_cloud_auth::credentials::user_account::Builder::new(authorized_user)
                .with_scopes(scopes.iter().map(AsRef::as_ref))
                .build()?;
        Ok(AuthorizedUserState { state, credentials })
    }

    async fn new_from_adc_json(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
        interactive_auth_message: impl AsRef<str>,
        oauth_callback_handler: OAuthCallback,
    ) -> anyhow::Result<Option<(Self, SystemTime)>> {
        let ret =
            match ApplicationDefaultCredentials::load_from_file(Some(&oauth_config.web.client_id))?
            {
                Some((adc @ ApplicationDefaultCredentials::AuthorizedUser(_), mtime)) => {
                    let state =
                        PersistedState::new(oauth_config, scopes.iter().map(AsRef::as_ref), adc);
                    let credentials = Self::create_credentials(&state).await?;
                    Some((
                        Self {
                            callback: oauth_callback_handler,
                            load_source: AuthorizedUserLoadSource::ADCJson,
                            persist_on_fetch: false,
                            oauth_config: oauth_config.clone(),
                            interactive_auth_message: interactive_auth_message.as_ref().to_string(),
                            inner: Arc::new(RwLock::new(AuthorizedUserState {
                                credentials,
                                state,
                            })),
                        },
                        mtime,
                    ))
                }
                _ => None,
            };
        Ok(ret)
    }

    async fn new_from_persisted_state(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
        interactive_auth_message: impl AsRef<str>,
        oauth_callback_handler: OAuthCallback,
    ) -> anyhow::Result<Option<(Self, SystemTime)>> {
        let ret = match PersistedState::load(oauth_config, scopes)? {
            Some((
                state @ PersistedState {
                    adc: ApplicationDefaultCredentials::AuthorizedUser(_),
                    ..
                },
                state_mtime,
            )) => {
                let credentials = Self::create_credentials(&state).await?;

                Some((
                    Self {
                        callback: oauth_callback_handler,
                        load_source: AuthorizedUserLoadSource::StateFile,
                        persist_on_fetch: false,
                        oauth_config: oauth_config.clone(),
                        interactive_auth_message: interactive_auth_message.as_ref().to_string(),
                        inner: Arc::new(RwLock::new(AuthorizedUserState { credentials, state })),
                    },
                    state_mtime,
                ))
            }
            _ => None,
        };
        Ok(ret)
    }

    fn order_clients_by_mtime(
        maybe_persisted: Option<(Self, SystemTime)>,
        maybe_adc: Option<(Self, SystemTime)>,
    ) -> Vec<Self> {
        match (maybe_persisted, maybe_adc) {
            (Some((persisted_client, persisted_mtime)), Some((adc_client, adc_mtime))) => {
                if persisted_mtime > adc_mtime {
                    tracing::debug!("Persisted state file was modified after ADC, trying it first");
                    vec![persisted_client, adc_client]
                } else {
                    tracing::debug!(
                        "ADC json file was modified after persisted state file, trying it first"
                    );
                    vec![adc_client, persisted_client]
                }
            }
            (Some((client, _)), None) | (None, Some((client, _))) => vec![client],
            (None, None) => vec![],
        }
    }

    /// Attempt to create a client based solely on files that are on disk that is *not* expired
    ///
    /// Attempts to look at both the persisted state file and application_default_credentials.json
    /// For each of those files that exist, we attempt to find the first one that is unexpired. We
    /// do this by attempting to fetch an access token.
    ///
    /// - The first client that returns an unexpired token is returned.
    /// - If the credentials are expired, that client is not used.
    /// - If any other error occurs when fetching an access token, that error is returned
    /// - If all of the found credentials are expired, `Ok(None)` is returned.
    ///
    /// If you want an attempt to be made to use the web auth flow if all credentials are expired,
    /// see [`Self::new`]
    ///
    /// Note: This method does both network and disk IO.
    pub async fn new_unexpired_from_disk(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
        interactive_auth_message: impl AsRef<str>,
    ) -> anyhow::Result<Option<Self>> {
        Self::new_unexpired_from_disk_with_callback(
            oauth_config,
            scopes,
            interactive_auth_message,
            handle_oauth_callback.into(),
        )
        .await
    }

    pub async fn new_unexpired_from_disk_with_callback(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
        interactive_auth_message: impl AsRef<str>,
        oauth_callback_handler: OAuthCallback,
    ) -> anyhow::Result<Option<Self>> {
        let interactive_auth_message = interactive_auth_message.as_ref();
        let maybe_persisted_client = Self::new_from_persisted_state(
            oauth_config,
            scopes,
            interactive_auth_message,
            oauth_callback_handler.clone(),
        )
        .await?;
        let maybe_adc_client = Self::new_from_adc_json(
            oauth_config,
            scopes,
            interactive_auth_message,
            oauth_callback_handler.clone(),
        )
        .await?;
        let clients = Self::order_clients_by_mtime(maybe_persisted_client, maybe_adc_client);

        for mut client in clients {
            tracing::debug!(
                "Verifying whether token is expired in client created from {}",
                client.load_source()
            );
            match client.get_access_token_impl().await {
                Ok(_) => {
                    tracing::debug!(
                        "Access token from client was valid. Persisting to state file, and returning client"
                    );
                    client.inner.write().await.state.persist()?;
                    client.persist_on_fetch = true;
                    return Ok(Some(client));
                }
                Err(AccessTokenError::RefreshTokenExpired(_)) => {
                    tracing::debug!(
                        "Access token from client created from {} was expired",
                        client.load_source()
                    );
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }

    /// Create a new instance of an authorized user, potentially interactively.
    ///
    /// This method attempts to load credentials from either a persisted state file (which might
    /// look for Application Default Credentials), or by presenting the web auth flow to the user.
    ///
    /// If state files exist on disk, then that client information will be used, and a new access
    /// token will be fetched if the old one does not exist, or is expired.
    ///   If `interactive` is true, then if the user credentials are expired, the web auth flow
    ///   will be initiated to update the refresh token.
    ///   If `interactive` is false, an error will be returned if the user credentials are expired.
    ///
    /// If there are no state files on disk, and `interactive` is true, then the user will
    /// authenticate through the web auth flow, and state will be persisted to disk. As part of
    /// this web auth flow, a message will be written to the user's console, even if stderr is
    /// being swallowed, letting them know that a browser is being opened.
    ///
    /// If there are no state files and `interactive` is *false*, an error will be returned.
    ///
    /// This method may be blocking on user input, and will write to both the network and disk.
    pub async fn new(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
        interactive: bool,
        interactive_auth_message: impl AsRef<str>,
    ) -> anyhow::Result<Self> {
        Self::new_with_callback(
            oauth_config,
            scopes,
            interactive,
            interactive_auth_message,
            handle_oauth_callback.into(),
        )
        .await
    }

    pub async fn new_with_callback(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
        interactive: bool,
        interactive_auth_message: impl AsRef<str>,
        oauth_callback_handler: OAuthCallback,
    ) -> anyhow::Result<Self> {
        let interactive_auth_message = interactive_auth_message.as_ref();

        match Self::new_unexpired_from_disk_with_callback(
            oauth_config,
            scopes,
            interactive_auth_message,
            oauth_callback_handler.clone(),
        )
        .await?
        {
            Some(client) => Ok(client),
            None if interactive => {
                let inner = Self::new_from_web(
                    oauth_config,
                    scopes,
                    true,
                    interactive_auth_message,
                    oauth_callback_handler.clone(),
                )
                .await?;
                Ok(Self {
                    callback: oauth_callback_handler,
                    load_source: AuthorizedUserLoadSource::WebAuthFlow,
                    persist_on_fetch: true,
                    oauth_config: oauth_config.clone(),
                    interactive_auth_message: interactive_auth_message.to_string(),
                    inner: Arc::new(RwLock::new(inner)),
                })
            }
            _ => Err(anyhow::anyhow!(
                "No user credentials were found, and an interactive session was not requested"
            )),
        }
    }

    /// Start a web server and go through the web flow to authenticate the user.
    ///
    /// In interactive sessions, this opens a user's web browser, but otherwise, will print out
    /// the link for the user to follow.
    async fn web_flow(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
        interactive_auth_message: impl AsRef<str>,
        oauth_callback_handler: OAuthCallback,
    ) -> anyhow::Result<reqwest::Response> {
        let scope = scopes.iter().map(AsRef::as_ref).join(" ");
        let callback_state = generate_callback_state();

        // Create a channel for receiving the auth code
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

        let expected_state = callback_state.state.clone();
        // Set up the server
        let app =
            Router::new()
                .route(
                    "/",
                    get(
                        move |Query(q): Query<AuthResponse>,
                              axum::extract::State(s): axum::extract::State<
                                  OAuthCallbackState,
                              >| async move {

                            if let Some(sender) = s.lock().await.take() {
                                if q.state != expected_state {
                                    let _ = sender.send(Err(CallbackError::StateMismatch  { received_state: q.state, expected_state }));
                                } else {
                                    let _ = sender.send(Ok(q.code));
                                }
                            }
                            oauth_callback_handler.call().await
                        },
                    ),
                )
                .with_state(tx);

        // Start the server
        let (listener, listening_url) = bind_available_port(
            &oauth_config.web.redirect_url,
            oauth_config.web.redirect_port_range.0,
            oauth_config.web.redirect_port_range.1,
        )
        .await?;

        tracing::info!("Server listening on {}", listening_url);

        let _server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_rx.unwrap_or_else(|_| ()))
                .await
                .expect("axum::server always returns Ok(())");
        });

        let _guard = scopeguard::guard(shutdown_tx, |s_tx| {
            let _ignored = s_tx.send(());
        });

        let url_encoded_params = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("access_type", "offline")
            .append_pair("client_id", &oauth_config.web.client_id)
            .append_pair("redirect_uri", &listening_url)
            .append_pair("response_type", "code")
            .append_pair("scope", &scope)
            .append_pair("prompt", "consent")
            .append_pair("state", &callback_state.state)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &callback_state.code_challenge)
            .finish();

        // Open the browser for authentication
        let auth_url = format!("{}?{}", oauth_config.web.auth_uri, url_encoded_params);

        tracing::info!("Request URL: {}", auth_url);

        // Print custom message to stderr if provided
        let interactive_auth_message = interactive_auth_message.as_ref();
        if !interactive_auth_message.is_empty() {
            let auth_message_with_url_interpolated =
                interactive_auth_message.replace("%url%", &auth_url);
            write_message_to_user(&auth_message_with_url_interpolated);
            // sleep for a bit so the message can be seen before a browser pops
            // up.
            tokio::time::sleep(Duration::from_millis(750)).await;
        }

        tracing::info!("Attempting to open browser for authentication...");
        if webbrowser::open(&auth_url).is_err() {
            tracing::info!(
                "Could not open a browser automatically. Please visit the link above to finish authenticating."
            );
        }

        // Wait for the auth code
        let auth_code = rx.await.context("Failed to receive auth code")??;

        // Exchange the code for a token
        let client = reqwest::Client::new();
        let token_response = client
            .post(&oauth_config.web.token_uri)
            .form(&[
                ("client_id", &oauth_config.web.client_id),
                ("client_secret", &oauth_config.web.client_secret),
                ("code", &auth_code),
                ("grant_type", &"authorization_code".to_string()),
                ("redirect_uri", &listening_url),
                ("code_verifier", &callback_state.code_verify),
            ])
            .send()
            .await
            .context("Failed to send token request")?;

        Ok(token_response)
    }
}

pub(crate) async fn handle_oauth_callback() -> Html<&'static str> {
    // Return a success page
    Html(
        r#"
        <html>
            <body>
                <h1>Authentication Successful!</h1>
                <p>You can close this window and return to the terminal.</p>
            </body>
        </html>
    "#,
    )
}

/// Attempt to write a message to the user via multiple means
///
/// - If in an interactive session, just write to stderr via eprintln
/// - If in a non-interactive session, and /dev/tty exists, write to it directly
/// - Otherwise, just try to write to stderr, and hope someone reads it :(
fn write_message_to_user(message: &str) {
    if std::io::stderr().is_terminal() {
        eprintln!("{}", message);
    } else if cfg!(target_os = "windows") {
        let message_with_newline = format!("{}\r\n", message);
        if let Err(e) = std::fs::write("CON", message_with_newline) {
            tracing::warn!("gtokenz: Could not open CON for writing - {}", e);
            eprintln!("{}", message);
        }
    } else if Path::new("/dev/tty").exists() {
        let message_with_newline = format!("{}\n", message);
        if let Err(e) = std::fs::write("/dev/tty", message_with_newline) {
            tracing::warn!("gtokenz: Could not open /dev/tty for writing - {}", e);
            eprintln!("{}", message);
        }
    } else {
        eprintln!("{}", message);
    }
}

struct CallbackState {
    state: String,
    code_challenge: String,
    code_verify: String,
}

#[derive(Debug, Clone, thiserror::Error)]
enum CallbackError {
    #[error("Got invalid state in callback. Expected {expected_state}, received {received_state}")]
    StateMismatch {
        expected_state: String,
        received_state: String,
    },
}

/// Generate the state, code_challenge and code_verify values
fn generate_callback_state() -> CallbackState {
    let code_verify: String = rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let digest = sha2::Sha256::digest(code_verify.as_bytes()).to_vec();
    let code_challenge = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(digest);

    let state: String = rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    CallbackState {
        state,
        code_challenge,
        code_verify,
    }
}

/// Attempts to listen on a set of ports until it finds an available one.
///
/// Returns the listener, and the http url for the server.
async fn bind_available_port(
    callback_url: &str,
    start_port: u16,
    end_port: u16,
) -> anyhow::Result<(tokio::net::TcpListener, String)> {
    let hostname = Url::parse(&callback_url.replace("%port%", "80"))
        .with_context(|| format!("Invalid callback url `{}` specified", callback_url))?
        .host_str()
        .ok_or_else(|| {
            anyhow!(
                "Invalid callback url `{}` specified. It must have a hostname",
                callback_url
            )
        })?
        .to_string();

    for port in start_port..end_port {
        let addr = format!("{hostname}:{port}");
        let resolved_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Could not resolve address {} to listen on", addr))?;

        match tokio::net::TcpListener::bind(&resolved_addr).await {
            Ok(l) => {
                return Ok((l, callback_url.replace("%port%", &port.to_string())));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tracing::debug!("Port {} on {} is unavailable: {}", port, hostname, e);
            }
            Err(e) => {
                return Err(anyhow::Error::from(e))
                    .with_context(|| format!("trying to bind to {}", addr));
            }
        }
    }
    Err(anyhow::anyhow!(
        "Could not bind to {} on any port between [{}, {}). Please close any processes using those ports and try again.",
        hostname,
        start_port,
        end_port
    ))
}

#[derive(Debug, serde::Deserialize)]
pub struct AuthResponse {
    pub code: String,
    pub state: String,
}

#[async_trait::async_trait]
impl TokenSource for AuthorizedUser {
    fn kind(&self) -> &'static str {
        "authorized user"
    }

    async fn credentials(&self) -> Credentials {
        self.inner.read().await.credentials.clone()
    }

    async fn get_access_token_impl(&self) -> Result<crate::token_source::Token, AccessTokenError> {
        let (new_token, new_state) = {
            let inner = self.inner.read().await;
            let now = chrono::Utc::now();
            if let Some(t) = inner.state.access_token(now) {
                tracing::debug!("Access token from state file was not expired as of {}", now);
                return Ok(t);
            }
            let new_token = fetch_token_from_google_sdk(inner.credentials.clone()).await?;
            let new_state = inner
                .state
                .clone()
                .with_access_token(new_token.clone())
                .await?;
            (new_token, new_state)
        };

        let mut writer = self.inner.write().await;
        writer.state = new_state;
        if self.persist_on_fetch {
            writer.state.persist()?;
        }
        Ok(new_token)
    }

    async fn refresh(&self) -> anyhow::Result<()> {
        let mut writer = self.inner.write().await;
        let new_inner = Self::new_from_web(
            &self.oauth_config,
            &writer.state.scopes,
            self.persist_on_fetch,
            self.interactive_auth_message.clone(),
            self.callback.clone(),
        )
        .await?;
        *writer = new_inner;
        Ok(())
    }

    async fn get_id_token_impl(&self) -> Result<crate::token_source::Token, IdTokenError> {
        let refresh_token = {
            let inner = self.inner.read().await;
            let now = chrono::Utc::now();
            if let Some(t) = inner.state.id_token(now) {
                tracing::debug!("ID token from state file was not expired as of {}", now);
                return Ok(t);
            }

            inner
                .state
                .adc
                .refresh_token()
                .ok_or(IdTokenError::MissingRefreshToken)
        }?;
        let request = IdTokenRequest {
            client_id: self.oauth_config.web.client_id.clone(),
            client_secret: self.oauth_config.web.client_secret.clone(),
            refresh_token,
            grant_type: "refresh_token".to_string(),
        };
        let new_token =
            fetch_id_token_from_google(&self.oauth_config.web.token_uri, &request).await?;
        let mut writer = self.inner.write().await;
        writer.state = writer
            .state
            .clone()
            .with_id_token(new_token.clone())
            .await?;
        writer.state.persist()?;
        Ok(new_token)
    }
}
