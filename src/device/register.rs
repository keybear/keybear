use crate::{
    app::AppState,
    body::EncryptedBody,
    device::{Device, ToDevice},
};
use actix_web::{
    error::{ErrorBadRequest, ErrorInternalServerError, ErrorNotFound},
    web::{Data, Json},
    Result as WebResult,
};
use anyhow::{anyhow, Context, Result};
use keybear_core::types::{NeedsVerificationDevice, RegisterDeviceRequest, RegisterDeviceResponse};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use uuid::Uuid;
use x25519_dalek::PublicKey;

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
            nonce: None,
        })
    }
}

impl Device {
    /// Create a public verification device of this device.
    pub fn to_needs_verification_device(
        &self,
        verification_code: &VerificationCode,
    ) -> NeedsVerificationDevice {
        NeedsVerificationDevice::new(&self.id, &self.name, verification_code.as_str())
    }
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
    // Extract the device from the JSON
    let register_device = register_device.into_inner();

    // Convert the register device into a device that we can put in the database
    let device = register_device
        .to_device()
        .map_err(ErrorInternalServerError)?;

    // Get the registered devices
    let mut devices = state
        .devices()
        .await
        // Convert the anyhow error to an internal server error
        .map_err(ErrorInternalServerError)?;
    if devices.is_empty() {
        // This is the first device, no need to verify it
        devices.register(device.clone());

        // Set the devices
        state
            .set_devices(devices)
            .await
            .map_err(ErrorInternalServerError)?;

        // TODO: return a different device type
        Ok(Json(
            device.to_register_device_result(&state.secret_key, ""),
        ))
    } else {
        // Get the list of devices that still need to be verified from the state
        let mut verification_devices = state
            .verification_devices()
            .await
            // Convert the anyhow error to an internal server error
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

    // Extract the object from the request and the client id
    let (verification_device, client_id) = verification_device
        .into_inner_with_client_id()
        // Convert the anyhow error to an internal server error
        .map_err(ErrorInternalServerError)?;

    // It's not allowed to verify from the device we are trying to register
    if verification_device.id().starts_with(&client_id) {
        return Err(ErrorBadRequest(
            "Can't verify from the device you are trying to register!",
        ));
    }

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
    state
        .set_devices(devices)
        .await
        .map_err(ErrorInternalServerError)?;

    // TODO: allow empty returns
    Ok(EncryptedBody::new(()))
}
