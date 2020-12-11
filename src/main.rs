#![forbid(unsafe_code)]

use anyhow::Result;
use clap::clap_app;
use lib::config::Config;
use log::{error, LevelFilter};
use std::fs;
use syslog::Facility;

#[actix_web::main]
async fn main() -> Result<()> {
    // Setup logging to syslog
    syslog::init(Facility::LOG_USER, LevelFilter::Debug, None)
        .expect("Setting up system log failed");

    // Function to check if a file arg exists
    let file_exists = |path: &str| {
        if fs::metadata(path).is_ok() {
            Ok(())
        } else {
            Err(String::from("File doesn't exist"))
        }
    };
    // Parse the command line arguments
    let matches = clap_app!(keybear =>
        (version: clap::crate_version!())
        (author: clap::crate_authors!())
        (about: clap::crate_description!())
        (@arg CONFIG: -c --config +takes_value {file_exists} "Sets a custom config file")
    )
    .get_matches();

    // Load the config TOML file
    let config = match matches.value_of("CONFIG") {
        // If a file is passed as an argument use that
        Some(config_path) => Config::from_file(config_path),
        // Otherwise try to get the default file location
        None => Config::from_default_file_or_empty(),
    }?;

    // Run the application
    lib::run(config).await.map_err(|err| {
        error!("Application crashed: {}", err);

        err
    })
}
