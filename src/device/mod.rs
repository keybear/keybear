use crate::app::AppState;
use actix_web::Result;
use paperclip::actix::{
    api_v2_operation,
    web::{Data, Json},
    Apiv2Schema, CreatedJson,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The string used to verify a device.
const DEVICE_VERIFICATION: &str = "keybear";

/// A list of endpoints.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct Devices {
    /// The devices.
    devices: Vec<Device>,
}

impl Devices {
    /// Register a new device.
    pub fn register(&mut self, device: Device) {
        self.devices.push(device);
    }

    /// Get the amount of devices registered.
    pub fn amount(&self) -> usize {
        self.devices.len()
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
}

/// A device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct Device {
    /// Random generated identifier of the device.
    id: String,
    /// Name of the device as configured by the user.
    name: String,
    /// The public key of the device.
    public_key: String,
}

impl Device {
    /// Verify the verification string with this client.
    pub fn verify(&self, verification: &str) -> bool {
        // TODO: use the encrypted verification
        verification == DEVICE_VERIFICATION
    }
}

/// A device registration struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct RegisterDevice {
    /// Name of the device as configured by the user.
    name: String,
    /// The public key of the device.
    public_key: String,
}

impl RegisterDevice {
    /// Convert this into a device struct that can be added to the database.
    pub fn to_device(&self) -> Device {
        Device {
            // Generate an identifier
            id: Uuid::new_v4().to_simple().to_string(),
            name: self.name.clone(),
            public_key: self.public_key.clone(),
        }
    }
}

/// Get a list of all device endpoints.
#[api_v2_operation]
pub async fn devices(state: Data<AppState>) -> Result<Json<Devices>> {
    Ok(Json(state.devices().await?))
}

/// Register a new device endpoint.
#[api_v2_operation]
pub async fn register(
    register_device: Json<RegisterDevice>,
    state: Data<AppState>,
) -> Result<CreatedJson<Device>> {
    // Get the list of devices from the state
    let mut devices = state.devices().await?;

    // Extract the device from the JSON
    let register_device = register_device.into_inner();

    // Register the passed device
    let device = register_device.to_device();
    devices.register(device.clone());

    // Set the devices
    state.set_devices(devices).await?;

    Ok(CreatedJson(device))
}

#[cfg(test)]
mod tests {
    use super::{Device, Devices, RegisterDevice};
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
        let devices: Devices =
            crate::test::perform_request(&mut app, "/devices", Method::GET).await;
        assert_eq!(devices.amount(), 0);
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
            public_key: "test_key".to_string(),
        };

        // Register the device
        let registered: Device =
            crate::test::perform_request_with_body(&mut app, "/register", Method::POST, &device)
                .await;
        assert_eq!(registered.name, device.name);
        assert_eq!(registered.public_key, device.public_key);

        // Verify that the list of devices is filled with it
        let devices: Devices =
            crate::test::perform_request(&mut app, "/devices", Method::GET).await;
        assert_eq!(devices.amount(), 1);
    }
}
