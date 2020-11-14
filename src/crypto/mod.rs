use anyhow::{anyhow, Result};
use ed25519_dalek::{Keypair, KEYPAIR_LENGTH};
use rand::rngs::OsRng;
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

/// Add functions to the crypto keypair to make it easier to use.
pub trait KeypairExt {
    /// Check whether there is a file containing the crypto keys.
    fn verify_file<P>(file: P) -> bool
    where
        P: AsRef<Path>;

    /// Generate a new keypair with the OS random number generator.
    fn generate_with_os_rand() -> Keypair;

    /// Try to load the crypto keys from our file on the disk.
    fn from_file<P>(file: P) -> Result<Keypair>
    where
        P: AsRef<Path>;

    /// Save the crypto keys to the file on the disk.
    fn save<P>(&self, file: P) -> Result<()>
    where
        P: AsRef<Path>;
}

impl KeypairExt for Keypair {
    fn verify_file<P>(file: P) -> bool
    where
        P: AsRef<Path>,
    {
        // TODO: add more checks
        file.as_ref().is_file()
    }

    fn generate_with_os_rand() -> Keypair {
        // Define a operating-system based random source
        let mut csprng = OsRng {};

        // Generate a keypair
        Keypair::generate(&mut csprng)
    }

    fn from_file<P>(file: P) -> Result<Keypair>
    where
        P: AsRef<Path>,
    {
        // Get the generic as the actual reference so it's traits can be used
        let file = file.as_ref();

        // Cannot load from disk if the file is not a valid one
        if !Self::verify_file(file) {
            return Err(anyhow!("Reading crypto keys from file {:?} failed", file));
        }

        // Read the file
        let mut f = File::open(file)
            .map_err(|err| anyhow!("Reading crypto keys from file {:?} failed: {}", file, err))?;

        // Read exactly the bytes from the file
        let mut bytes = [0; KEYPAIR_LENGTH];
        f.read_exact(&mut bytes).map_err(|err| {
            anyhow!(
                "Crypto keys file {:?} has wrong size, it might be corrupt: {}",
                file,
                err
            )
        })?;

        // Try to construct the keypair from the bytes
        Keypair::from_bytes(&bytes)
            .map_err(|err| anyhow!("Crypto keys file {:?} is invalid: {}", file, err))
    }

    fn save<P>(&self, file: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        // Get the generic as the actual reference so it's traits can be used
        let file = file.as_ref();

        // Try to write the keys as raw bytes to the disk
        fs::write(file, self.to_bytes())
            .map_err(|err| anyhow!("Could not write crypto keys to file {:?}: {}", file, err))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::KeypairExt;
    use anyhow::Result;
    use ed25519_dalek::Keypair;

    #[test]
    fn verify() -> Result<()> {
        // A non-existing file means it's not a valid file for the keys
        assert_eq!(Keypair::verify_file("/definitily/should/not/exist"), false);

        Ok(())
    }

    #[test]
    fn save_and_load() -> Result<()> {
        // Create a temporary directory for the test database
        let dir = tempfile::tempdir()?;
        // Create the temporary file to save the key in
        let file = dir.path().join("key");

        // Generate a new pair of keys.
        let keypair = Keypair::generate_with_os_rand();

        // Save the keypair
        keypair.save(&file)?;

        // Load the saved keypair from disk
        let disk_keypair = Keypair::from_file(file)?;

        // Check if they are the same
        assert_eq!(keypair.to_bytes(), disk_keypair.to_bytes());

        // Close the directory
        dir.close()?;

        Ok(())
    }
}
