use crate::authorized_user::OAuthCallback;

/// Various pieces of configuration to control how [`crate::auto_detect`], [`crate::AuthorizedUser`], etc work.
#[derive(Clone)]
pub struct DtokenzConfig {
    /// Whether to allow interactive authentication prompts
    ///
    /// Defaults to `true`
    pub interactive: bool,
    /// If an interactive authentication method is selected, print this message to the user
    ///
    /// The string '%url%' will be replaced with the OAuth2 URL when displayed
    pub interactive_auth_message: Option<String>,

    /// The callback to invoke after successfully authenticating interactively.
    ///
    /// Generally just a function that takes no parameters, and returns a string, or something
    /// that can be converted into a [`axum::response::Response`].
    ///
    /// Defaults to [`crate::authorized_user::default_oauth_callback_handler`]
    pub oauth_callback_handler: OAuthCallback,
    /// How long to wait for a user to complete the interactive authentication flow before aborting.
    ///
    /// Defaults to 2 minutes.
    pub interactive_auth_timeout: std::time::Duration,
}

impl Default for DtokenzConfig {
    fn default() -> Self {
        Self {
            interactive: true,
            interactive_auth_message: None,
            oauth_callback_handler: crate::authorized_user::default_oauth_callback_handler.into(),
            interactive_auth_timeout: std::time::Duration::from_mins(2),
        }
    }
}
