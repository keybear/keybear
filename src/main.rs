mod store;

use anyhow::Result;
use clap::{clap_app, crate_authors, crate_description, crate_version};
use log::{debug, error, trace, LevelFilter};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
};
use syslog::{Facility, Formatter3164};

const DEFAULT_PORT: u16 = 52477;

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
        (@arg PORT: -p --port +takes_value "Override the default port")
    )
    .get_matches();

    let port = matches.value_of_t::<u16>("PORT").unwrap_or(DEFAULT_PORT);

    // Setup logging to syslog
    syslog::init(Facility::LOG_USER, LevelFilter::Debug, None)
        .expect("Setting up system log failed");

    // Start the Tor server
    let socket = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = TcpListener::bind(socket)?;
    debug!("Listening on {:?}", socket);

    loop {
        // Block until we get a connection
        let (mut stream, addr) = listener.accept()?;
        if addr.ip() != Ipv4Addr::LOCALHOST {
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
