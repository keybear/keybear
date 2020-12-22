use crate::{app::AppState, body::EncryptedBody};
use actix_web::{
    error::ErrorInternalServerError,
    web::{Data, Json},
    Result as WebResult,
};
use anyhow::{anyhow, Context, Result};
use keybear_core::{
    crypto,
    types::{PublicDevice, RegisterDeviceRequest, RegisterDeviceResponse},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::convert::TryInto;
use uuid::Uuid;
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
        PublicDevice::new(&self.id, &self.name)
    }

    /// Create the result when registering a new device.
    pub fn to_register_device_result(&self, server_key: &StaticSecret) -> RegisterDeviceResponse {
        RegisterDeviceResponse::new(&self.id, &self.name, &PublicKey::from(server_key))
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

impl ToDevice for RegisterDeviceRequest {
    /// Convert this into a device struct that can be added to the database.
    fn to_device(&self) -> Result<Device> {
        // Read exactly the bytes from the public key
        let bytes: [u8; 32] = base64::decode(self.public_key())
            .context("Device public key is invalid")?
            .try_into()
            .map_err(|_| anyhow!("Device public key is invalid"))?;
        let public_key = PublicKey::from(bytes);

        // Generate a new unique identifier
        let id = Uuid::new_v4().to_simple().to_string();

        Ok(Device {
            name: self.name().to_string(),
            id,
            public_key,
        })
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

/// Register a new device endpoint.
pub async fn register(
    register_device: Json<RegisterDeviceRequest>,
    state: Data<AppState>,
) -> WebResult<Json<RegisterDeviceResponse>> {
    // Get the list of devices from the state
    let mut devices = state
        .devices()
        .await
        // Convert the anyhow error to an internal server error
        .map_err(ErrorInternalServerError)?;

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
