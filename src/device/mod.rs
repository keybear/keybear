use crate::{app::AppState, body::EncryptedBody};
use actix_web::{
    error::ErrorInternalServerError,
    web::{Data, Json},
    Result as WebResult,
};
use anyhow::{anyhow, Context, Result};
use keybear_core::crypto;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::convert::TryInto;
use uuid::Uuid;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

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

    /// Get a vector of devices as allowed to be shown to the clients.
    pub fn to_public_vec(&self) -> Vec<PublicDevice> {
        self.devices
            .iter()
            .map(|device| device.to_public_device())
            .collect()
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
}

impl Device {
    /// Create a public view device of this device.
    pub fn to_public_device(&self) -> PublicDevice {
        PublicDevice {
            id: self.id.clone(),
            name: self.name.clone(),
        }
    }

    /// Create the result when registering a new device.
    pub fn to_register_device_result(&self, server_key: &StaticSecret) -> RegisterDeviceResult {
        RegisterDeviceResult {
            id: self.id.clone(),
            name: self.name.clone(),
            server_public_key: base64::encode(PublicKey::from(server_key).as_bytes()),
        }
    }

    /// Encrypt a object to send.
    pub fn encrypt<T>(&self, server_key: &StaticSecret, obj: &T) -> Result<Vec<u8>>
    where
        T: Serialize,
    {
        crypto::encrypt(&self.shared_key(server_key), obj)
    }

    /// Decrypt a message to receive.
    pub fn decrypt<T>(&self, server_key: &StaticSecret, cipher_bytes: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        crypto::decrypt(&self.shared_key(server_key), cipher_bytes)
    }

    /// Get the shared key to communicate with this device.
    pub fn shared_key(&self, server_key: &StaticSecret) -> SharedSecret {
        server_key.diffie_hellman(&self.public_key)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicDevice {
    /// Unique identifier.
    pub id: String,
    /// Name of the device.
    pub name: String,
}

/// A device registration struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterDevice {
    /// Name of the device as configured by the user.
    name: String,
    /// The public key of the device encoded as base64.
    public_key: String,
}

impl RegisterDevice {
    /// Construct a new device.
    pub fn new(name: &str, public_key: &PublicKey) -> Self {
        Self {
            name: name.to_string(),
            public_key: base64::encode(public_key.as_bytes()),
        }
    }

    /// Convert this into a device struct that can be added to the database.
    pub fn to_device(&self) -> Result<Device> {
        // Read exactly the bytes from the public key
        let bytes: [u8; 32] = base64::decode(self.public_key.clone())
            .context("Device public key is invalid")?
            .try_into()
            .map_err(|_| anyhow!("Device public key is invalid"))?;
        let public_key = PublicKey::from(bytes);

        // Generate a new unique identifier
        let id = Uuid::new_v4().to_simple().to_string();

        Ok(Device {
            name: self.name.clone(),
            id,
            public_key,
        })
    }
}

/// The result from successfully registering a device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterDeviceResult {
    /// Unique identifier.
    pub id: String,
    /// Name of the device as configured by the user.
    pub name: String,
    /// The public key of the server.
    server_public_key: String,
}

impl RegisterDeviceResult {
    /// Get the public key of the server.
    pub fn server_public_key(&self) -> Result<PublicKey> {
        // Read exactly the bytes from the public key
        let bytes: [u8; 32] = base64::decode(self.server_public_key.clone())
            .context("Device public key is invalid")?
            .try_into()
            .map_err(|_| anyhow!("Device public key is invalid"))?;

        Ok(PublicKey::from(bytes))
    }
}

/// Get a list of all device endpoints.
pub async fn devices(state: Data<AppState>) -> WebResult<EncryptedBody<Vec<PublicDevice>>> {
    Ok(EncryptedBody::new(
        state
            .devices()
            .await
            // Convert the anyhow error to an internal server error
            .map_err(|err| ErrorInternalServerError(err))?
            .to_public_vec(),
    ))
}

/// Register a new device endpoint.
pub async fn register(
    register_device: Json<RegisterDevice>,
    state: Data<AppState>,
) -> WebResult<Json<RegisterDeviceResult>> {
    // Get the list of devices from the state
    let mut devices = state
        .devices()
        .await
        // Convert the anyhow error to an internal server error
        .map_err(|err| ErrorInternalServerError(err))?;

    // Extract the device from the JSON
    let register_device = register_device.into_inner();

    // Convert the register device into a device that we can put in the database
    let device = register_device
        .to_device()
        .map_err(ErrorInternalServerError)?;

    // Register the passed device
    devices.register(device.clone());

    // Set the devices
    state.set_devices(devices).await?;

    // Return a view of the device
    Ok(Json(device.to_register_device_result(&state.secret_key)))
}
