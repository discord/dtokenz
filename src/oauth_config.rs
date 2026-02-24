use std::borrow::ToOwned;
use std::string::ToString;
use std::sync::LazyLock;

pub static CLOUD_SDK_CONFIG: LazyLock<OAuthConfig> = LazyLock::new(|| OAuthConfig {
    // Taken from https://github.com/google-cloud-sdk-unofficial/google-cloud-sdk/blob/9fc25425c512c85e409609c9e972b28fe38f1491/lib/googlecloudsdk/core/config.py#L182
    web: WebConfig {
        client_id: "32555940559.apps.googleusercontent.com".to_string(),
        client_secret: "ZmssLNjJy2998hD4CTg2ejr2".to_string(),
        auth_uri: "https://accounts.google.com/o/oauth2/auth".to_string(),
        token_uri: "https://oauth2.googleapis.com/token".to_string(),
        redirect_uris: vec!["http://localhost:8286".to_owned()],
        default_scopes: vec![
            "openid".to_owned(),
            "https://www.googleapis.com/auth/userinfo.email".to_owned(),
            "https://www.googleapis.com/auth/cloud-platform".to_owned(),
            "https://www.googleapis.com/auth/appengine.admin".to_owned(),
            "https://www.googleapis.com/auth/sqlservice.login".to_owned(),
            "https://www.googleapis.com/auth/compute".to_owned(),
            "https://www.googleapis.com/auth/accounts.reauth".to_owned(),
        ],
    },
});

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct OAuthConfig {
    pub web: WebConfig,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct WebConfig {
    pub client_id: String,
    pub client_secret: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub redirect_uris: Vec<String>,

    #[serde(skip)]
    pub default_scopes: Vec<String>,
}
