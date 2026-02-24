//! # dtokenz
//!
//! The`dtokenz` crate adds a higher level abstraction over [google-cloud-auth](https://docs.rs/google-cloud-auth/latest/google_cloud_auth/) that makes configuration and use simpler.
//!
//! The goal of this rust library is to make retrieving an authentication token for use in other binaries as simple as possible, regardless of the environment that it is being called in, and with as little interactivity as possible. This simplification of the API is a key advantage over other tools like [gcloud](https://docs.cloud.google.com/sdk/gcloud) and [oauth2l](https://github.com/google/oauth2l), where each type of account (service account, MDS client, etc) have different interfaces, and have to be taken into account for every client application. At the same time, this library also makes it so that the [GCP rust library](https://github.com/googleapis/google-cloud-rust) can still be used with its own [native authentication types](https://docs.rs/google-cloud-auth/latest/google_cloud_auth/credentials/struct.Credentials.html).
//!
//! This library supports fetching both [access tokens](https://docs.cloud.google.com/docs/authentication/token-types#access-tokens), and [id tokens](https://cloud.google.com/docs/authentication/token-types#id) for:
//! - Authorized Users (individuals in a GCP organization)
//! - Service Accounts via private key
//! - Service Accounts via Google Metadata Service for hosts running in GCP.
//!
//! The main entry point to this library is the [`auto_detect`]/[`auto_detect_singleton`] method. See its documentation for more details about how `dtokenz` decides to authenticate.
//! The only configuration needed is an instance of [`oauth_config::OAuthConfig`]
//!
//! ## Example
//!
//!```rust,no_run
//! use dtokenz::{TokenSource, CLOUD_SDK_CONFIG, auto_detect_singleton};
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let interactive_auth_message = "Opening browser to %url%";
//!     let token_source = auto_detect_singleton(
//!            CLOUD_SDK_CONFIG.clone(),
//!            &CLOUD_SDK_CONFIG.web.default_scopes,
//!            true,
//!            interactive_auth_message,
//!     ).await?;
//!     let access_token = token_source.get_access_token().await?;
//!     let id_token = token_source.get_id_token().await?;
//!     eprintln!("Got access token {}, id token {}", access_token.token, id_token.token);
//!     Ok(())
//! }
//! ```

#![deny(clippy::all)]
#![allow(clippy::uninlined_format_args)]
#![deny(clippy::unwrap_used)]

pub mod application_default_credentials;
pub mod authorized_user;
pub mod metadata_service;
pub mod oauth_config;
pub mod service_account;
mod state;
pub mod token_source;

pub use authorized_user::AuthorizedUser;
pub use metadata_service::MetadataService;
pub use oauth_config::CLOUD_SDK_CONFIG;
pub use oauth_config::OAuthConfig;
pub use service_account::ServiceAccount;
pub use token_source::TokenSource;
pub use token_source::auto_detect;
pub use token_source::auto_detect_singleton;
pub use token_source::auto_detect_with_callback;
