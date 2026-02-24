use crate::application_default_credentials::ApplicationDefaultCredentials;
use crate::oauth_config::OAuthConfig;
use anyhow::Context;
use itertools::Itertools;
use sha2::Digest;
use std::path::PathBuf;

// Per google-cloud-auth-0.22.4/src/token_cache.rs, use ~4 minutes of slack
// in determining when a local token is expired. This gives us time to both
// get the token, but also *use* said token.
const VALID_TOKEN_SLACK: chrono::Duration = chrono::Duration::seconds(240);

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
pub(crate) struct PersistedToken {
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// Extra state that is stored after first authenticating
///
/// For now this includes things like the id token, however in the future, this also
/// can contain things like the last access token used.
///
/// This contains within it the entirety of the parsed ApplicationDefaultCredentials file
/// so that we can pass it directly to the Google SDK apis.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
pub(crate) struct PersistedState {
    oauth_client_id: String,
    pub scopes: Vec<String>,
    access_token: Option<PersistedToken>,
    id_token: Option<PersistedToken>,
    #[serde(flatten)]
    pub adc: ApplicationDefaultCredentials,
}

impl PersistedState {
    pub(crate) async fn with_access_token(
        self,
        token: crate::token_source::Token,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            access_token: Some(PersistedToken {
                token: token.token,
                expires_at: token.expires_at,
            }),
            ..self
        })
    }

    pub(crate) async fn with_id_token(
        self,
        token: crate::token_source::Token,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            id_token: Some(PersistedToken {
                token: token.token,
                expires_at: token.expires_at,
            }),
            ..self
        })
    }

    /// Get an access token from the persisted state as long as it has not expired.
    pub(crate) fn access_token(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<crate::token_source::Token> {
        self.access_token.as_ref().and_then(|t| {
            tracing::debug!(
                "Access token expiration is {}; checking against {}",
                t.expires_at,
                now + VALID_TOKEN_SLACK
            );
            if t.expires_at > now + VALID_TOKEN_SLACK {
                Some(crate::token_source::Token {
                    token: t.token.clone(),
                    expires_at: t.expires_at,
                })
            } else {
                None
            }
        })
    }

    /// Get an id token from the persisted state as long as it has not expired.
    pub(crate) fn id_token(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<crate::token_source::Token> {
        self.id_token.as_ref().and_then(|t| {
            tracing::debug!(
                "ID token expiration is {}; checking against {}",
                t.expires_at,
                now + VALID_TOKEN_SLACK
            );
            if t.expires_at > now + VALID_TOKEN_SLACK {
                Some(crate::token_source::Token {
                    token: t.token.clone(),
                    expires_at: t.expires_at,
                })
            } else {
                None
            }
        })
    }

    fn path(client_id: &str, scopes: &[impl AsRef<str>]) -> anyhow::Result<PathBuf> {
        let mut hasher = sha2::Sha256::new();
        for scope in scopes.iter().map(|s| s.as_ref()).sorted() {
            hasher.update(scope);
        }
        let scopes_hash = hex::encode(hasher.finalize());
        let filename = format!("state-{client_id}-{scopes_hash}.json");
        Ok(dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot find home directory"))?
            .join(".config")
            .join("gcloud")
            .join("dtokenz")
            .join(filename))
    }

    pub(crate) fn new(
        oauth_config: &OAuthConfig,
        scopes: impl Iterator<Item = impl Into<String>>,
        adc: ApplicationDefaultCredentials,
    ) -> Self {
        Self {
            oauth_client_id: oauth_config.web.client_id.clone(),
            scopes: scopes.into_iter().map(Into::into).collect(),
            adc,
            access_token: None,
            id_token: None,
        }
    }

    /// Attempt to load a persisted state from disk. Return that state and when it was last modified.
    pub(crate) fn load(
        oauth_config: &OAuthConfig,
        scopes: &[impl AsRef<str>],
    ) -> anyhow::Result<Option<(Self, std::time::SystemTime)>> {
        let path = Self::path(&oauth_config.web.client_id, scopes)?;
        if path.exists() {
            let mtime = std::fs::metadata(&path)
                .with_context(|| format!("Fetching metadata from {}", path.display()))?
                .modified()
                .with_context(|| format!("Getting last modified time from {}", path.display()))?;
            let js = std::fs::read_to_string(&path)
                .with_context(|| format!("Loading state file from {}", path.display()))?;
            let ret = serde_json::from_str(&js)
                .with_context(|| format!("Deserializing state file from {}", path.display()))?;
            Ok(Some((ret, mtime)))
        } else {
            Ok(None)
        }
    }

    /// Write the state into a json file
    ///
    /// There are no inter-thread or inter-process guarantees here. The only guarantee that is
    /// given is that a write-to-dir-then-move process will be followed.
    pub(crate) fn persist(&self) -> anyhow::Result<()> {
        let path = Self::path(&self.oauth_client_id, &self.scopes)?;
        let Some(parent) = path.parent() else {
            return Err(anyhow::anyhow!(
                "No parent was found for the state file at {}",
                path.display()
            ));
        };
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating directory {}", parent.display()))?;
        let temp = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(&temp, &self)
            .with_context(|| format!("Serializing state file to {}", path.display()))?;
        temp.persist(&path)
            .with_context(|| format!("Writing state file to {}", path.display()))?;

        Ok(())
    }
}
