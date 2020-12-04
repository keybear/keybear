#![forbid(unsafe_code)]

mod app;
mod config;
mod crypto;
mod device;
mod net;
mod password;
mod store;

use crate::{crypto::KeypairExt, store::StorageBuilder};
use actix_web::{middleware::Logger, App, HttpServer};
use anyhow::Result;
use clap::{clap_app, crate_authors, crate_description, crate_version};
use config::Config;
use ed25519_dalek::Keypair;
use log::LevelFilter;
use paperclip::actix::OpenApiExt;
use std::net::{Ipv4Addr, SocketAddrV4};
use syslog::Facility;

#[actix_web::main]
async fn main() -> Result<()> {
    // Function to check if a file arg exists
    let file_exists = |path: &str| {
        if std::fs::metadata(path).is_ok() {
            Ok(())
        } else {
            Err(String::from("File doesn't exist"))
        }
    };

    // Parse the command line arguments
    let matches = clap_app!(keybear =>
        (version: crate_version!())
        (author: crate_authors!())
        (about: crate_description!())
        (@arg CONFIG: -c --config +takes_value {file_exists} "Sets a custom config file")
    )
    .get_matches();

    // Load the config TOML file
    let config = match matches.value_of("config") {
        // If a file is passed as an argument use that
        Some(config_path) => Config::from_file(config_path),
        // Otherwise try to get the default file location
        None => Config::from_default_file_or_empty(),
    }?;

    // Setup logging to syslog
    syslog::init(Facility::LOG_USER, LevelFilter::Debug, None)
        .expect("Setting up system log failed");

    // TODO: wrap everything underneath here in a function of which the result get's logged

    // Generate a keypair if it doesn't exist
    let _key = Keypair::from_file_or_generate(config.key_path())?;

    // Setup the database
    let storage = StorageBuilder::new(config.database_path()).build()?;

    // Start the Tor server
    Ok(HttpServer::new(move || {
        App::new()
            // Configure the routes and services
            .configure(app::config_app)
            // Attach the database
            .data(storage.clone())
            // Use the default logging service
            .wrap(Logger::default())
            // Use the paperclip API service
            .wrap_api()
            // Expose the JSON OpenAPI spec
            .with_json_spec_at("/api/spec")
            // Paperclip requires us to build the app
            .build()
    })
    .bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.server_port()))?
    .run()
    .await?)
}
