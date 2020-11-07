mod store;
mod tor;

use crate::tor::service;
use anyhow::Result;
use clap::{clap_app, crate_authors, crate_description, crate_version};
use std::process;

fn main() -> Result<()> {
    let matches = clap_app!(keybear =>
        (version: crate_version!())
        (author: crate_authors!())
        (about: crate_description!())
    )
    .get_matches();

    if !service::is_running()? {
        eprintln!("Tor service is not running, please start it");
        process::exit(1);
    }

    Ok(())
}
