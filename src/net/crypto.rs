use rusqlite::{Connection, Result};
use std::path::PathBuf;

/// Structure to setup the [`Crypto`](./struct.Crypto.html) struct for encoding & decoding messages.
#[derive(Debug)]
pub struct CryptoBuilder {
    database_path: PathBuf,
}

impl CryptoBuilder {
    /// Start a new builder, the database file location must be passed.
    pub fn new<P>(database_path: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            database_path: database_path.into(),
        }
    }

    /// Construct the crypto struct.
    pub fn build(self) -> Result<Crypto> {
        Ok(Crypto {
            db: Connection::open(self.database_path)?,
        })
    }
}

/// Structure to decode & encode messages.
#[derive(Debug)]
pub struct Crypto {
    /// The SQLite database containing the keys.
    db: Connection,
}

#[cfg(test)]
mod tests {
    use crate::net::crypto::CryptoBuilder;
    use anyhow::Result;
    use tempdir::TempDir;

    #[test]
    fn new_database() -> Result<()> {
        // Create a temporary directory for the test database
        let dir = TempDir::new("keybear_test")?;

        // Construct the crypto with a new database.
        let _crypto = CryptoBuilder::new(dir.path().join("test_db.sqlite")).build()?;

        // Close the directory
        dir.close()?;

        Ok(())
    }
}
