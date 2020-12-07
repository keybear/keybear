pub mod middleware;

use anyhow::{anyhow, bail, Result};
use log::{debug, info};
use rand::rngs::OsRng;
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};
use x25519_dalek::StaticSecret;

/// Add functions to the crypto secret key to make it easier to use.
pub trait StaticSecretExt {
    /// Check whether there is a file containing the crypto keys.
    fn verify_file<P>(file: P) -> bool
    where
        P: AsRef<Path>;

    /// Generate a new secret key with the OS random number generator.
    fn new_with_os_rand() -> StaticSecret;

    /// Try to load the crypto keys from our file on the disk.
    fn from_file<P>(file: P) -> Result<StaticSecret>
    where
        P: AsRef<Path>;

    /// Save the crypto keys to the file on the disk.
    fn save<P>(&self, file: P) -> Result<()>
    where
        P: AsRef<Path>;

    /// Try to load the crypto key or generate a new one.
    fn from_file_or_generate<P>(file: P) -> Result<StaticSecret>
    where
        P: AsRef<Path>,
    {
        if Self::verify_file(&file) {
            // The file exists, open it
            Self::from_file(file)
        } else {
            // The file doesn't exist, generate a new one and save it
            let key = Self::new_with_os_rand();
            key.save(file)?;

            Ok(key)
        }
    }
}

impl StaticSecretExt for StaticSecret {
    fn verify_file<P>(file: P) -> bool
    where
        P: AsRef<Path>,
    {
        // Get the generic as the actual reference so it's traits can be used
        let file = file.as_ref();

        debug!("Verifying file \"{}\"", file.display());

        // TODO: add more checks
        file.is_file()
    }

    fn new_with_os_rand() -> StaticSecret {
        // Get the generic as the actual reference so it's traits can be used
        info!("Generating new secret key");

        // Define a operating-system based random source
        let mut csprng = OsRng {};

        // Generate a secret key
        StaticSecret::new(&mut csprng)
    }

    fn from_file<P>(file: P) -> Result<StaticSecret>
    where
        P: AsRef<Path>,
    {
        // Get the generic as the actual reference so it's traits can be used
        let file = file.as_ref();

        info!("Loading secret key from file \"{}\"", file.display());

        // Cannot load from disk if the file is not a valid one
        if !Self::verify_file(file) {
            bail!("Reading crypto keys from file {:?} failed", file);
        }

        // Read the file
        let mut f = File::open(file)
            .map_err(|err| anyhow!("Reading crypto keys from file {:?} failed: {}", file, err))?;

        // Read exactly the bytes from the file
        let mut bytes = [0; 32];
        f.read_exact(&mut bytes).map_err(|err| {
            anyhow!(
                "Crypto keys file {:?} has wrong size, it might be corrupt: {}",
                file,
                err
            )
        })?;

        // Try to construct the secret key from the bytes
        Ok(StaticSecret::from(bytes))
    }

    fn save<P>(&self, file: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        // Get the generic as the actual reference so it's traits can be used
        let file = file.as_ref();

        info!("Saving secret key to file \"{}\"", file.display());

        // Try to write the keys as raw bytes to the disk
        fs::write(file, self.to_bytes())
            .map_err(|err| anyhow!("Could not write crypto keys to file {:?}: {}", file, err))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::StaticSecretExt;
    use anyhow::Result;
    use x25519_dalek::StaticSecret;

    #[test]
    fn default() -> Result<()> {
        // Create a temporary directory for the test database
        let dir = tempfile::tempdir()?;
        // Create the temporary file to save the key in
        let file = dir.path().join("key");

        // Try to load the file, which will fail and generate a new file
        StaticSecret::from_file_or_generate(file)?;

        Ok(())
    }

    #[test]
    fn verify() {
        // A non-existing file means it's not a valid file for the keys
        assert_eq!(
            StaticSecret::verify_file("/definitily/should/not/exist"),
            false
        );
    }

    #[test]
    fn save_and_load() -> Result<()> {
        // Create a temporary directory for the test database
        let dir = tempfile::tempdir()?;
        // Create the temporary file to save the key in
        let file = dir.path().join("key");

        // Generate a new pair of keys.
        let secret = StaticSecret::new_with_os_rand();

        // Save the secret key
        secret.save(&file)?;

        // Load the saved secret key from disk
        let disk_secret = StaticSecret::from_file(file)?;

        // Check if they are the same
        assert_eq!(secret.to_bytes(), disk_secret.to_bytes());

        // Close the directory
        dir.close()?;

        Ok(())
    }
}
