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

/// An [external account] credential file, as written by
/// `gcloud iam workload-identity-pools create-cred-config` or by hand.
///
/// Only the fields dtokenz itself inspects are named; everything else (`client_id`,
/// `universe_domain`, `service_account_impersonation`, ...) is kept verbatim in `extra`
/// so the whole document can be handed to the Google SDK unchanged.
///
/// [external account]: https://google.aip.dev/auth/4117
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ExternalAccountDetails {
    /// The workload identity pool provider, e.g.
    /// `//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/q`.
    pub audience: String,
    /// The type of the subject token, e.g. `urn:ietf:params:oauth:token-type:jwt`.
    pub subject_token_type: String,
    /// The Security Token Service endpoint.
    pub token_url: String,
    /// When set, the Google SDK impersonates this service account for *every* access token,
    /// and dtokenz mints ID tokens as it. When unset, access tokens belong to the federated
    /// principal itself; see [`crate::ExternalAccount`] for how ID tokens are handled then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_impersonation_url: Option<String>,
    /// Where the subject token comes from (`file`, `url` or `executable`). Passed through.
    pub credential_source: serde_json::Value,
    /// Any other fields in the file, preserved verbatim.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ExternalAccountDetails {
    /// The whole credential document, including the `type` tag, in the shape the Google SDK's
    /// [`google_cloud_auth::credentials::external_account::Builder`] expects.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({ "type": "external_account" });
        if let (Some(target), Ok(serde_json::Value::Object(fields))) =
            (value.as_object_mut(), serde_json::to_value(self))
        {
            target.extend(fields);
        }
        value
    }

    /// Like [`Self::to_json`], but without `service_account_impersonation_url`, so the
    /// resulting credentials are the federated principal rather than an impersonated account.
    pub fn to_json_without_impersonation(&self) -> serde_json::Value {
        let mut value = self.to_json();
        if let Some(fields) = value.as_object_mut() {
            fields.remove("service_account_impersonation_url");
        }
        value
    }

    /// The service account named by `service_account_impersonation_url`, if any.
    ///
    /// The URL has the shape
    /// `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<email>:generateAccessToken`.
    pub fn impersonated_service_account(&self) -> Option<String> {
        let url = self.service_account_impersonation_url.as_deref()?;
        let (_, rest) = url.split_once("/serviceAccounts/")?;
        let email = rest.split(':').next()?;
        (!email.is_empty()).then(|| email.to_string())
    }
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
    ExternalAccount(ExternalAccountDetails),
}

impl ApplicationDefaultCredentials {
    /// Get the refresh token if possible. This is only set for authorized users.
    pub(crate) fn refresh_token(&self) -> Option<String> {
        match self {
            ApplicationDefaultCredentials::AuthorizedUser(authorized_user) => {
                Some(authorized_user.refresh_token.clone())
            }
            ApplicationDefaultCredentials::ServiceAccount(_)
            | ApplicationDefaultCredentials::ExternalAccount(_) => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn external_account_json() -> serde_json::Value {
        serde_json::json!({
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/buildkite/providers/buildkite-base",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1/token",
            "credential_source": { "file": "/tmp/oidc.jwt", "format": { "type": "text" } },
            "universe_domain": "googleapis.com"
        })
    }

    #[test]
    fn parses_external_account_and_preserves_unknown_fields() -> anyhow::Result<()> {
        let adc: ApplicationDefaultCredentials = serde_json::from_value(external_account_json())?;
        let ApplicationDefaultCredentials::ExternalAccount(details) = &adc else {
            anyhow::bail!("expected external account, got {adc:?}");
        };
        assert_eq!(details.token_url, "https://sts.googleapis.com/v1/token");
        assert_eq!(details.service_account_impersonation_url, None);
        assert_eq!(details.impersonated_service_account(), None);
        assert_eq!(
            details.extra.get("universe_domain"),
            Some(&serde_json::Value::String("googleapis.com".into()))
        );
        assert_eq!(adc.refresh_token(), None);

        // Round-trips through the tagged enum and back out to the exact same document.
        assert_eq!(serde_json::to_value(&adc)?, external_account_json());
        assert_eq!(details.to_json(), external_account_json());
        Ok(())
    }

    #[test]
    fn strips_impersonation_url_and_extracts_the_account() -> anyhow::Result<()> {
        let mut json = external_account_json();
        json["service_account_impersonation_url"] = serde_json::Value::String(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken".into(),
        );
        let adc: ApplicationDefaultCredentials = serde_json::from_value(json.clone())?;
        let ApplicationDefaultCredentials::ExternalAccount(details) = adc else {
            anyhow::bail!("expected external account");
        };
        assert_eq!(
            details.impersonated_service_account().as_deref(),
            Some("sa@p.iam.gserviceaccount.com")
        );
        assert_eq!(details.to_json(), json);

        let stripped = details.to_json_without_impersonation();
        assert!(stripped.get("service_account_impersonation_url").is_none());
        assert_eq!(stripped["audience"], json["audience"]);
        assert_eq!(stripped["type"], "external_account");
        Ok(())
    }

    #[test]
    fn other_account_types_still_parse() -> anyhow::Result<()> {
        let adc: ApplicationDefaultCredentials = serde_json::from_value(serde_json::json!({
            "type": "authorized_user",
            "client_id": "cid",
            "client_secret": "secret",
            "refresh_token": "rt"
        }))?;
        assert_eq!(adc.refresh_token().as_deref(), Some("rt"));
        Ok(())
    }
}
