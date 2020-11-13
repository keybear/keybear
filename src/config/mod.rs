use anyhow::{anyhow, Result};
use log::debug;
use serde::Deserialize;
use std::{fmt::Debug, fs, path::Path};

// Default location of the configuration file
pub const DEFAULT_CONFIG_FILE_PATH: &str = "/var/lib/keybear/config.toml";

// Default values for the configuration file
pub const DEFAULT_PRIVATE_KEY_PATH: &str = "/var/lib/keybear/private_key";
pub const DEFAULT_PORT: u16 = 52477;

/// The application configuration.
#[derive(Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Config {
    /// Location of the file containing the private key.
    private_key_path: Option<String>,
    /// Information about things like the ports to run on.
    server: Option<ServerConfig>,
}

impl Config {
    /// Try to load the file from the default path.
    ///
    /// If the file doesn't exist use a default configuration.
    pub fn from_default_file_or_empty() -> Result<Self> {
        if Path::new(DEFAULT_CONFIG_FILE_PATH).exists() {
            // The configuration file exists, try to load it
            Self::from_file(DEFAULT_CONFIG_FILE_PATH)
        } else {
            // No configuration file founds, just use the defaults
            Ok(Self::default())
        }
    }

    /// Load the config from a file.
    pub fn from_file<P>(file: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        // Get the generic as the actual reference so it's traits can be used
        let file = file.as_ref();

        debug!("Reading configuration file {:?}", file);

        // Attempt to open the configuration file
        let contents = fs::read_to_string(file)
            .map_err(|err| anyhow!("Reading configuration file {:?} failed: {}", file, err))?;

        Self::from_str(&contents)
    }

    /// Create the config from a string with all defaults filled.
    pub fn from_str(toml: &str) -> Result<Self> {
        toml::from_str(&toml)
            .map_err(|err| anyhow!("Reading keybear configuration failed: {}", err))
    }

    /// Path of the private key.
    pub fn private_key_path(&self) -> &Path {
        self.private_key_path
            .as_ref()
            // Convert the string to a path
            .map(|path_str| Path::new(path_str))
            // If no string is set use the default value
            .unwrap_or(Path::new(DEFAULT_PRIVATE_KEY_PATH))
    }

    /// Port to use that the Tor hidden service tries to connect to.
    pub fn server_port(&self) -> u16 {
        self.server
            .as_ref()
            // Get the value from the server if it's set
            .map(|server| server.port())
            // Otherwise use the default
            .unwrap_or(DEFAULT_PORT)
    }
}

/// Configuration table for the server.
#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct ServerConfig {
    /// Port to listen to the Tor hidden service.
    port: Option<u16>,
}

impl ServerConfig {
    /// Port to use that the Tor hidden service tries to connect to.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{self, Config};
    use anyhow::Result;
    use std::path::Path;

    #[test]
    fn defaults() -> Result<()> {
        let config = Config::from_str("")?;
        // The default values should be the same as loading from an empty string
        assert_eq!(config, Config::default());

        // Verify the default values
        assert_eq!(
            config.private_key_path(),
            Path::new(config::DEFAULT_PRIVATE_KEY_PATH)
        );
        assert_eq!(config.server_port(), config::DEFAULT_PORT);

        Ok(())
    }

    #[test]
    fn default_non_existing_file() -> Result<()> {
        let config = Config::from_default_file_or_empty()?;
        assert_eq!(config, Config::default());

        Ok(())
    }
}
