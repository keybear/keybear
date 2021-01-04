use crate::{app::AppState, body::EncryptedBody};
use actix_web::{
    error::{ErrorBadRequest, ErrorInternalServerError, ErrorNotFound},
    web::{Data, Json},
    Result as WebResult,
};
use anyhow::{anyhow, Context, Result};
use keybear_core::{
    crypto,
    types::{NeedsVerificationDevice, PublicDevice, RegisterDeviceRequest, RegisterDeviceResponse},
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCode(String);

impl VerificationCode {
    /// Generate a new random string of words.
    pub fn generate() -> Self {
        VerificationCode(chbs::passphrase())
    }

    /// Get the code.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for VerificationCode {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

/// A list of endpoints awaiting registration.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VerificationDevices {
    /// Tuples of devices with the verification strings.
    devices: Vec<(VerificationCode, Device)>,
}

impl VerificationDevices {
    /// Register a new device.
    pub fn register(&mut self, device: Device, verification_code: VerificationCode) {
        self.devices.push((verification_code, device));
    }

    /// Get a device with the ID.
    pub fn find(&self, id: &str) -> Option<&(VerificationCode, Device)> {
        // Find the device by ID
        self.devices.iter().find(|(_, device)| device.id == id)
    }

    /// Remove a verification device from the list.
    pub fn remove(&mut self, id: &str) {
        self.devices.retain(|(_, device)| device.id != id)
    }

    /// Get a vector of devices that need to be registered as allowed to be shown to the clients.
    pub fn to_needs_verification_vec(&self) -> Vec<NeedsVerificationDevice> {
        self.devices
            .iter()
            .map(|(verification_code, device)| {
                device.to_needs_verification_device(verification_code)
            })
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

    /// Create a public verification device of this device.
    pub fn to_needs_verification_device(
        &self,
        verification_code: &VerificationCode,
    ) -> NeedsVerificationDevice {
        NeedsVerificationDevice::new(&self.id, &self.name, verification_code.as_str())
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

/// Get a list of all device endpoints that need to be verified.
pub async fn verification_devices(
    state: Data<AppState>,
) -> WebResult<EncryptedBody<Vec<NeedsVerificationDevice>>> {
    Ok(EncryptedBody::new(
        state
            .verification_devices()
            .await
            // Convert the anyhow error to an internal server error
            .map_err(ErrorInternalServerError)?
            .to_needs_verification_vec(),
    ))
}

/// Register a new device endpoint.
pub async fn register(
    register_device: Json<RegisterDeviceRequest>,
    state: Data<AppState>,
) -> WebResult<Json<RegisterDeviceResponse>> {
    // Get the list of devices that still need to be verified from the state
    let mut verification_devices = state
        .verification_devices()
        .await
        // Convert the anyhow error to an internal server error
        .map_err(ErrorInternalServerError)?;

    // Extract the device from the JSON
    let register_device = register_device.into_inner();

    // Convert the register device into a device that we can put in the database
    let device = register_device
        .to_device()
        .map_err(ErrorInternalServerError)?;

    // Generate a new verification code
    let verification_code = VerificationCode::generate();

    // Register the passed device
    verification_devices.register(device.clone(), verification_code.clone());

    // Set the devices
    state.set_verification_devices(verification_devices).await?;

    // Return a view of the device
    Ok(Json(device.to_register_device_result(
        &state.secret_key,
        verification_code.as_str(),
    )))
}

/// Verify a device.
pub async fn verify(
    verification_device: EncryptedBody<NeedsVerificationDevice>,
    state: Data<AppState>,
) -> WebResult<EncryptedBody<()>> {
    // Get the list of devices that still need to be verified from the state
    let mut verification_devices = state
        .verification_devices()
        .await
        // Convert the anyhow error to an internal server error
        .map_err(ErrorInternalServerError)?;

    // Extract the object from the request
    let verification_device = verification_device.into_inner();

    // Find the device with the matching ID
    let (verification_code, device) = verification_devices
        .find(verification_device.id())
        .ok_or_else(|| {
            ErrorNotFound(format!(
                "Device with ID \"{}\" does not exist",
                verification_device.id()
            ))
        })?;

    // Check that the verification codes match
    if verification_code != verification_device.verification_code() {
        return Err(ErrorBadRequest("Device verification code mismatch"));
    }

    // The verification code is valid, register the device

    // Add the verification device to the registered devices
    let mut devices = state
        .devices()
        .await
        // Convert the anyhow error to an internal server error
        .map_err(ErrorInternalServerError)?;
    devices.register(device.clone());

    // Remove the verification device
    verification_devices.remove(verification_device.id());

    // Set the devices
    state.set_verification_devices(verification_devices).await?;
    state.set_devices(devices).await?;

    // TODO: allow empty returns
    Ok(EncryptedBody::new(()))
}
