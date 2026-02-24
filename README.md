# Dtokenz - Fast and Easy Token Fetching for GCP

## What is this?

The`dtokenz` rust crate adds a higher level abstraction over [google-cloud-auth](https://docs.rs/google-cloud-auth/latest/google_cloud_auth/) that makes configuration and use simpler.

The goal of this rust library is to make retrieving an authentication token for use in other binaries as simple as possible, regardless of the environment that it is being called in, and with as little interactivity as possible. This simplification of the API is a key advantage over other tools like [gcloud](https://docs.cloud.google.com/sdk/gcloud) and [oauth2l](https://github.com/google/oauth2l), where each type of account (service account, MDS client, etc) have different interfaces, and have to be taken into account for every client application. At the same time, this library also makes it so that the [GCP rust library](https://github.com/googleapis/google-cloud-rust) can still be used with its own [native authentication types](https://docs.rs/google-cloud-auth/latest/google_cloud_auth/credentials/struct.Credentials.html).

This library supports fetching both [access tokens](https://docs.cloud.google.com/docs/authentication/token-types#access-tokens) and [id tokens](https://cloud.google.com/docs/authentication/token-types#id) for:

- Authorized Users (individuals in a GCP organization)
- Service Accounts via private key
- Service Accounts via Google Metadata Service for hosts running in GCP.

The main entry point to this library is the `auto_detect`/`auto_detect_singleton` method. The only configuration needed is an instance of `OauthConfig`. By default we provide the Google SDK one.

Very roughly, this method tries to figure out the least obtrusive way to fetch a token possible. The order it tries is:

- Non-expired Authorized User credentials
- Service account application default credentials
- The GCP Metadata service
- Authorized User credentials, created / refreshed potentially interactively.

The more detailed heuristic is:

- Attempt to load authorized user credentials from disk. If they are present and NOT EXPIRED then return that authorized user.
- Attempt to load service account json from GOOGLE_APPLICATION_CREDENTIALS or application_default_credentials.json (in ~/.config/gcloud/application_default_credentials.json). If the json file exists and has the right account type in it, then a service account client will be returned.
- If GOOGLE_APPLICATION_CREDENTIALS is not set, attempt to see if there is a metadata service, and use that if possible. This will prefer service accounts on e.g. GCP hosts, so if a specific authorized user account is needed, do not use this method.
- If after all of that, we still don't have a client, attempt to get an authorized user client. If `interactive` is true, then if no credentials are already configured, the web flow will be initialized. If `interactive` is false, an error will be returned. See `AuthorizedUser` for more details about how interactive authentication works.

## Web auth flow

If dtokenz attempts to initiate an interactive user authentication, it will:

- Start up a webserver on port 127.0.0.1:8286
- Tell the user via stderr / /dev/tty the URL that is about to be opened (this message is customizable)
- Open a browser tab, launching into the [web authentication flow](https://developers.google.com/identity/protocols/oauth2/web-server).
- Once the user has logged in, dtokenz stores the refresh token amongst other information like the expiration date and proceeds.
- Future invocations should be automatically refreshed if possible. If the refresh operation fails, an interactive flow is launched again.

## Example

```rust,no_run
use dtokenz::{TokenSource, CLOUD_SDK_CONFIG, auto_detect_singleton};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let interactive_auth_message = "Opening browser to %url%";
    let token_source = auto_detect_singleton(
           CLOUD_SDK_CONFIG.clone(),
           &CLOUD_SDK_CONFIG.web.default_scopes,
           true,
           interactive_auth_message,
    ).await?;
    let access_token = token_source.get_access_token().await?;
    let id_token = token_source.get_id_token().await?;
    eprintln!("Got access token {}, id token {}", access_token.token, id_token.token);
    Ok(())
}
```
