#![forbid(unsafe_code)]

pub mod app;
pub mod config;
pub mod crypto;
pub mod device;
pub mod net;
pub mod password;
pub mod store;
// Due to integration tests not taking `[cfg(test)]` this has to be exposed publicly
pub mod test;

use actix_web::{middleware::Logger, App, HttpServer};
use anyhow::Result;
use app::AppState;
use config::Config;
use paperclip::actix::web::Data;
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
