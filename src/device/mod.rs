pub mod nonce;
pub mod register;

use crate::{app::AppState, body::EncryptedBody};
use actix_web::{error::ErrorInternalServerError, web::Data, Result as WebResult};
use anyhow::{anyhow, bail, Result};
use keybear_core::{
    crypto,
    types::{PublicDevice, RegisterDeviceResponse},
};
use log::{debug, trace};
use nonce::SerializableNonce;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Allow converting an incoming message to a device.
trait ToDevice {
    fn to_device(&self) -> Result<Device>;
}

/// A list of endpoints.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Devices {
    /// The devices.
    devices: Vec<Device>,
}

impl Devices {
    /// Register a new device.
    pub fn register(&mut self, device: Device) {
        self.devices.push(device);
    }

    /// Get a device with the ID.
    pub fn find(&self, id: &str) -> Option<&Device> {
        // Find the device by ID
        self.devices.iter().find(|device| device.id == id)
    }

    /// Override a device.
    pub fn set(&mut self, device: &Device) {
        self.devices.iter_mut().for_each(|cached| {
            if cached.id == device.id {
                *cached = device.clone();
            }
        });
    }

    /// Get a vector of devices as allowed to be shown to the clients.
    pub fn to_public_vec(&self) -> Vec<PublicDevice> {
        self.devices
            .iter()
            .map(|device| device.to_public_device())
            .collect()
    }

    /// Whether there are no registered devices.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

/// A device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    /// Random generated identifier of the device.
    id: String,
    /// Name of the device as configured by the user.
    name: String,
    /// The public key of the device.
    public_key: PublicKey,
    /// A single use nonce.
    nonce: Option<SerializableNonce>,
}

impl Device {
    /// Create a public view device of this device.
    pub fn to_public_device(&self) -> PublicDevice {
        PublicDevice::new(&self.id, &self.name)
    }

    /// Create the result when registering a new device.
    pub fn to_register_device_result(
        &self,
        server_key: &StaticSecret,
        verification_code: &str,
    ) -> RegisterDeviceResponse {
        RegisterDeviceResponse::new(
            &self.id,
            &self.name,
            &PublicKey::from(server_key),
            verification_code,
        )
    }

    /// Generate a nonce.
    pub fn generate_nonce(&mut self) {
        debug!("Generating nonce for device \"{}\"", self.id);

        self.nonce = Some(SerializableNonce::generate());
    }

    /// Reset the nonce so it a new one needs to be requested.
    pub fn clear_nonce(&mut self) {
        trace!("Clearing nonce for device \"{}\"", self.id);

        self.nonce = None;
    }

    /// Encrypt a object to send.
    pub fn encrypt<T>(&self, server_key: &StaticSecret, obj: &T) -> Result<Vec<u8>>
    where
        T: Serialize,
    {
        match &self.nonce {
            Some(nonce) => crypto::encrypt(&self.shared_key(server_key), &nonce.to_nonce(), obj),
            None => bail!("Could not encrypt response because no nonce was saved for this device"),
        }
    }

    /// Decrypt a message to receive.
    pub fn decrypt<T>(&self, server_key: &StaticSecret, cipher_bytes: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        match &self.nonce {
            Some(nonce) => crypto::decrypt(
                &self.shared_key(server_key),
                &nonce.to_nonce(),
                cipher_bytes,
            ),
            None => bail!("Could not decrypt request because no nonce was saved for this device"),
        }
    }

    /// Get the shared key to communicate with this device.
    pub fn shared_key(&self, server_key: &StaticSecret) -> SharedSecret {
        server_key.diffie_hellman(&self.public_key)
    }

    /// Get the nonce, throw an error when it's not set.
    pub fn nonce(&self) -> Result<&SerializableNonce> {
        self.nonce
            .as_ref()
            .ok_or_else(|| anyhow!("No nonce generated yet"))
    }
}

/// Get a list of all device endpoints.
pub async fn devices(state: Data<AppState>) -> WebResult<EncryptedBody<Vec<PublicDevice>>> {
    Ok(EncryptedBody::new(
        state
            .devices()
            .await
            // Convert the anyhow error to an internal server error
            .map_err(ErrorInternalServerError)?
            .to_public_vec(),
    ))
}
