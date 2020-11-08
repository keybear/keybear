mod store;

use anyhow::Result;
use clap::{clap_app, crate_authors, crate_description, crate_version};
use log::{debug, trace};
use std::io::{Read};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

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

    // Start the Tor server
    let socket = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = TcpListener::bind(socket)?;
    debug!("Listening on {:?}", socket);

    loop {
        // Block until we get a connection
        let (mut tcp_stream, addr) = listener.accept()?;
        trace!("Connection from {:?} received", addr);

        // Get the request
        let mut input = String::new();
        let _ = tcp_stream.read_to_string(&mut input)?;
        println!("{}", input);
    }

    Ok(())
}
