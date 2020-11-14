use anyhow::Result;
use sled::Db;
use std::path::PathBuf;

/// Structure to setup the [`Storage`](./struct.Storage.html) struct for encoding & decoding messages.
#[derive(Debug)]
pub struct StorageBuilder {
    database_path: PathBuf,
}

impl StorageBuilder {
    /// Start a new builder, the database file location must be passed.
    pub fn new<P>(database_path: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            database_path: database_path.into(),
        }
    }

    /// Construct the storage struct.
    pub fn build(self) -> Result<Storage> {
        Ok(Storage {
            db: sled::open(self.database_path)?,
        })
    }
}

/// Structure to decode & encode messages.
#[derive(Debug)]
pub struct Storage {
    /// The database containing the keys.
    db: Db,
}

#[cfg(test)]
mod tests {
    use crate::store::StorageBuilder;
    use anyhow::Result;

    #[test]
    fn new_database() -> Result<()> {
        // Create a temporary directory for the test database
        let dir = tempfile::tempdir()?;

        // Construct the storage with a new database.
        let _storage = StorageBuilder::new(dir.path().join("test.db")).build()?;

        // Close the directory
        dir.close()?;

        Ok(())
    }
}
