#![forbid(unsafe_code)]

pub mod app;
pub mod body;
pub mod config;
pub mod device;
pub mod net;
pub mod password;
pub mod route;
pub mod store;
// Due to integration tests not taking `[cfg(test)]` this has to be exposed publicly
pub mod test;

use actix_web::{middleware::Logger, web::Data, App, HttpServer};
use anyhow::Result;
use app::AppState;
use config::Config;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Run the keybear server.
pub async fn run(config: Config) -> Result<()> {
    // Setup the application state.
    let state = Data::new(AppState::from_config(&config)?);

    // Start the Tor server
    Ok(HttpServer::new(move || {
        app::fill_app(
            App::new()
                // Use the default logging service
                .wrap(Logger::default()),
            &state,
        )
    })
    // Disable TCP keep alive
    .keep_alive(None)
    // Bind to the Tor service using the port from the config
    .bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.server_port()))?
    .run()
    .await?)
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use anyhow::Result;
    use keybear_core::crypto::StaticSecretExt;
    use x25519_dalek::StaticSecret;

    #[actix_rt::test]
    async fn invalid_key_path() -> Result<()> {
        let config = Config::from_raw_str("key_path = \"/non-existing/path\"")?;
        assert!(super::run(config).await.is_err());

        Ok(())
    }

    #[actix_rt::test]
    async fn invalid_database_path() -> Result<()> {
        // Create a temporary directory for the test database
        let dir = tempfile::tempdir()?;
        // Create the temporary file to save the key in
        let file = dir.path().join("key");

        // Generate a new pair of keys.
        let secret = StaticSecret::new_with_os_rand();

        // Save the secret key
        secret.save(&file)?;

        // Create the config with the valid key
        let config = Config::from_raw_str(&format!(
            r#"
            key_path = "{}"
            database_path = "/non-existing/path"
            "#,
            file.to_str().unwrap(),
        ))?;
        // The database should now not be able to be created
        assert!(super::run(config).await.is_err());

        Ok(())
    }
}
