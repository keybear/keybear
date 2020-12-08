use crate::app::AppState;
use actix_web::{error::ErrorInternalServerError, Result as WebResult};
use anyhow::{anyhow, Context, Result};
use paperclip::actix::{
    api_v2_operation,
    web::{Data, Json},
    Apiv2Schema, CreatedJson,
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use uuid::Uuid;
use x25519_dalek::PublicKey;

/// The string used to verify a device.
const DEVICE_VERIFICATION: &str = "keybear";

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

    /// Verify a device.
    pub fn verify(&self, id: &str, verification: &str) -> bool {
        // Find the device by ID
        if let Some(device) = self.devices.iter().find(|device| device.id == id) {
            device.verify(verification)
        } else {
            false
        }
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
    /// Verify the verification string with this client.
    pub fn verify(&self, verification: &str) -> bool {
        // TODO: use the encrypted verification
        verification == DEVICE_VERIFICATION
    }

    /// Create a public view device of this device.
    pub fn to_public_device(&self) -> PublicDevice {
        PublicDevice {
            id: self.id.clone(),
            name: self.name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct PublicDevice {
    /// Unique identifier.
    id: String,
    /// Name of the device.
    name: String,
}

/// A device registration struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct RegisterDevice {
    /// Name of the device as configured by the user.
    name: String,
    /// The public key of the device encoded as base64.
    public_key: String,
}

impl RegisterDevice {
    /// Convert this into a device struct that can be added to the database.
    pub fn to_device(&self) -> Result<Device> {
        // Read exactly the bytes from the public key
        let bytes: [u8; 32] = base64::decode(self.public_key.clone())
            .context("Device public key is invalid")?
            .try_into()
            .map_err(|_| anyhow!("Device public key is invalid"))?;

        Ok(Device {
            // Generate a new unique identifier
            id: Uuid::new_v4().to_simple().to_string(),
            name: self.name.clone(),
            public_key: PublicKey::from(bytes),
        })
    }
}

/// Get a list of all device endpoints.
#[api_v2_operation]
pub async fn devices(state: Data<AppState>) -> WebResult<Json<Vec<PublicDevice>>> {
    Ok(Json(state.devices().await?.to_public_vec()))
}

/// Register a new device endpoint.
#[api_v2_operation]
pub async fn register(
    register_device: Json<RegisterDevice>,
    state: Data<AppState>,
) -> WebResult<CreatedJson<PublicDevice>> {
    // Get the list of devices from the state
    let mut devices = state.devices().await?;

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
    Ok(CreatedJson(device.to_public_device()))
}

#[cfg(test)]
mod tests {
    use super::{PublicDevice, RegisterDevice};
    use actix_web::{http::Method, test, web, App};

    #[actix_rt::test]
    async fn devices() {
        let mut app = test::init_service(
            App::new()
                .service(web::resource("/devices").route(web::get().to(super::devices)))
                .app_data(crate::test::app_state()),
        )
        .await;

        // Request the devices, empty list should be returned
        let devices: Vec<PublicDevice> =
            crate::test::perform_request(&mut app, "/devices", Method::GET).await;
        assert_eq!(devices.len(), 0);
    }

    #[actix_rt::test]
    async fn register() {
        let mut app = test::init_service(
            App::new()
                .service(web::resource("/register").route(web::post().to(super::register)))
                .service(web::resource("/devices").route(web::get().to(super::devices)))
                .app_data(crate::test::app_state()),
        )
        .await;

        // Setup a device to get the JSON from
        let device = RegisterDevice {
            name: "test_name".to_string(),
            // Use an empty public key
            public_key: base64::encode([0u8; 32]),
        };

        // Register the device
        let registered: PublicDevice =
            crate::test::perform_request_with_body(&mut app, "/register", Method::POST, &device)
                .await;
        assert_eq!(registered.name, device.name);

        // Verify that the list of devices is filled with it
        let devices: Vec<PublicDevice> =
            crate::test::perform_request(&mut app, "/devices", Method::GET).await;
        assert_eq!(devices.len(), 1);
    }
}
