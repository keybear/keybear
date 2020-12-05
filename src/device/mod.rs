use actix_storage::Storage;
use actix_web::Result;
use paperclip::actix::{
    api_v2_operation,
    web::{Data, Json},
    Apiv2Schema, CreatedJson,
};
use serde::{Deserialize, Serialize};

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
}

/// An endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct Device {
    /// Name of the device as configured by the user.
    name: String,
    /// Public ED25519 key.
    public_key: String,
}

/// Get a list of all device endpoints.
#[api_v2_operation]
pub async fn devices(storage: Data<Storage>) -> Result<Json<Devices>> {
    // Get the devices from the database or use the default
    let devices = storage
        .get("devices")
        .await?
        .unwrap_or_else(Devices::default);

    dbg!(&devices);

    Ok(Json(devices))
}

/// Register a new device endpoint.
#[api_v2_operation]
pub async fn register(device: Json<Device>, storage: Data<Storage>) -> Result<CreatedJson<Device>> {
    // Get the devices from the database or use the default
    let mut devices = storage
        .get("devices")
        .await?
        .unwrap_or_else(Devices::default);

    // Extract the device from the JSON
    let device = device.into_inner();

    // Register the passed device
    devices.register(device.clone());

    // Persist the devices in the storage
    storage.set("devices", &devices).await?;

    Ok(CreatedJson(device))
}

#[cfg(test)]
mod tests {
    use super::{Device, Devices};
    use actix_storage::Storage;
    use actix_storage_hashmap::HashMapStore;
    use actix_web::{http::Method, test, web, App};

    #[actix_rt::test]
    async fn devices() {
        let mut app = test::init_service(
            App::new()
                .service(web::resource("/devices").route(web::get().to(super::devices)))
                .data(Storage::build().store(HashMapStore::default()).finish()),
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
                .data(Storage::build().store(HashMapStore::default()).finish()),
        )
        .await;

        // Setup a device to get the JSON from
        let device = Device {
            name: "test".to_string(),
            public_key: "test_key".to_string(),
        };

        // Register the device
        let registered: Device =
            crate::test::perform_request_with_body(&mut app, "/register", Method::POST, &device)
                .await;
        assert_eq!(registered, device);

        // Verify that the list of devices is filled with it
        let devices: Devices =
            crate::test::perform_request(&mut app, "/devices", Method::GET).await;
        assert_eq!(devices.amount(), 1);
    }
}
