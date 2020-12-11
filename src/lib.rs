#![forbid(unsafe_code)]

pub mod app;
pub mod config;
pub mod crypto;
pub mod device;
pub mod net;
pub mod password;
pub mod store;
#[cfg(test)]
pub mod test;

use crate::app::AppState;
use actix_web::{middleware::Logger, App, HttpServer};
use anyhow::Result;
use config::Config;
use paperclip::{
    actix::{web::Data, OpenApiExt},
    v2::models::{DefaultApiRaw, Info},
};
use std::net::{Ipv4Addr, SocketAddrV4};

/// Run the keybear server.
pub async fn run(config: Config) -> Result<()> {
    // Setup the application state.
    let appstate = Data::new(AppState::from_config(&config)?);

    // Define the API spec
    let mut spec = DefaultApiRaw::default();
    spec.info = Info {
        version: clap::crate_version!().to_string(),
        title: clap::crate_name!().to_string(),
        description: Some(clap::crate_description!().to_string()),
        ..Default::default()
    };

    // Start the Tor server
    Ok(HttpServer::new(move || {
        App::new()
            // Attach the database
            .app_data(appstate.clone())
            // Use the default logging service
            .wrap(Logger::default())
            // Use the paperclip API service
            .wrap_api_with_spec(spec.clone())
            // Configure the routes and services
            .configure(app::router)
            // Expose the JSON OpenAPI spec
            .with_json_spec_at("/api/spec")
            // Paperclip requires us to build the app
            .build()
    })
    // Disable TCP keep alive
    .keep_alive(None)
    // Bind to the Tor service using the port from the config
    .bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.server_port()))?
    .run()
    .await?)
}
