#![forbid(unsafe_code)]

mod command;
mod config;
mod net;
mod store;

use anyhow::Result;
use clap::{clap_app, crate_authors, crate_description, crate_version};
use config::Config;
use log::{debug, error, trace, LevelFilter};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
};
use syslog::Facility;

fn main() -> Result<()> {
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
    let socket = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.server_port());
    let listener = TcpListener::bind(socket)?;
    debug!("Listening on {:?}", socket);

    loop {
        // Block until we get a connection
        let (mut stream, addr) = listener.accept()?;
        if !net::is_valid_client_ip(addr.ip()) {
            error!("External non-Tor connection initiated from address {:?}, this means your server might be compromised!", addr);

            // We only accept connections from the Tor hidden service on the same machine
            continue;
        }

        trace!("Connection from {:?} received", addr);

        // Get the request
        let mut buffer = [0; 1024];
        stream.read(&mut buffer)?;

        let (status_line, contents) = if buffer.starts_with(b"GET / HTTP/1.1\r\n") {
            ("HTTP/1.1 200 OK\r\n\r\n", "Hi there")
        } else {
            ("HTTP/1.1 404 NOT FOUND\r\n\r\n", "Sorry not found")
        };

        let response = format!("{}{}", status_line, contents);

        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}
