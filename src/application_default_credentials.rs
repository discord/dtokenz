use anyhow::Context;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AuthorizedUserDetails {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_project_id: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ServiceAccountDetails {
    /// The client email address of the service account.
    /// (e.g., "my-sa@my-project.iam.gserviceaccount.com")
    pub client_email: String,
    /// ID of the service account's private key
    pub private_key_id: String,
    /// The PEM-encoded PKCS#8 private key string associated with the service account.
    /// Begins with `-----BEGIN PRIVATE KEY-----`.
    pub private_key: String,
    /// The project id the service account belongs to.
    pub project_id: String,
    /// The universe domain this service account belongs to.
    pub universe_domain: Option<String>,
}

/// The various fields that are in an application_default_credentials.json file that we care about.
///
/// These vary based on account type.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum ApplicationDefaultCredentials {
    AuthorizedUser(AuthorizedUserDetails),
    ServiceAccount(ServiceAccountDetails),
}

impl ApplicationDefaultCredentials {
    /// Get the refresh token if possible. This is only set for authorized users.
    pub(crate) fn refresh_token(&self) -> Option<String> {
        match self {
            ApplicationDefaultCredentials::AuthorizedUser(authorized_user) => {
                Some(authorized_user.refresh_token.clone())
            }
            ApplicationDefaultCredentials::ServiceAccount(_) => None,
        }
    }

    /// The path to the standard application_default_credentials.json file
    pub(crate) fn standard_path() -> anyhow::Result<PathBuf> {
        Ok(dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?
            .join(".config")
            .join("gcloud")
            .join("application_default_credentials.json"))
    }

    /// Attempts to load ApplicationDefaultCredentials if the file exists, and if the type and client id match.
    ///
    /// If the GOOGLE_APPLICATION_CREDENTIALS environment variable is set, that path will be used,
    /// otherwise [`Self::standard_path()`] will be used.
    ///
    /// If loaded successfully, the ADC and the file's last modified time is returned.
    pub(crate) fn load_from_file(
        client_id: Option<&str>,
    ) -> anyhow::Result<Option<(Self, SystemTime)>> {
        let path = if let Some(path) = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS") {
            PathBuf::from(path)
        } else {
            Self::standard_path()?
        };
        if !path.exists() {
            return Ok(None);
        }
        let mtime = std::fs::metadata(&path)
            .with_context(|| format!("Fetching metadata from {}", path.display()))?
            .modified()
            .with_context(|| format!("Getting last modified time from {}", path.display()))?;
        let js_str = std::fs::read_to_string(&path)
            .with_context(|| format!("Reading ADC file at {}", path.display()))?;
        let decoded: Self = serde_json::from_str(&js_str)
            .with_context(|| format!("Decoding ADC file at {}", path.display()))?;

        if let (Some(cid), Self::AuthorizedUser(authorized_user)) = (client_id, &decoded) {
            if authorized_user.client_id == cid {
                Ok(Some((decoded, mtime)))
            } else {
                Ok(None)
            }
        } else {
            Ok(Some((decoded, mtime)))
        }
    }
}
