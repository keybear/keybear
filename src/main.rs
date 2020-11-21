#![forbid(unsafe_code)]

mod command;
mod config;
mod crypto;
mod net;
mod store;

use crate::net::TorGuard;
use actix_web::{get, guard::Not, web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use clap::{clap_app, crate_authors, crate_description, crate_version};
use config::Config;
use log::LevelFilter;
use std::net::{Ipv4Addr, SocketAddrV4};
use syslog::Facility;

/// Get a list of all users.
#[get("/users/")]
async fn users() -> impl Responder {
    HttpResponse::Ok().body("Hello world")
}

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

    // Start the Tor server
    Ok(HttpServer::new(|| {
        App::new()
            .service(web::scope("/users").service(users).guard(TorGuard))
            // Deny everything that's opened from outside the tor connection
            .default_service(
                web::route()
                    .guard(Not(TorGuard))
                    .to(|| HttpResponse::MethodNotAllowed()),
            )
    })
    .bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.server_port()))?
    .run()
    .await?)
}
