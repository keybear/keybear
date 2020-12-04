use actix_storage::Storage;
use actix_web::Result;
use paperclip::actix::{
    api_v2_operation,
    web::{Data, Json},
    Apiv2Schema, CreatedJson,
};
use serde::{Deserialize, Serialize};

/// A list of endpoints.
#[derive(Debug, Default, Serialize, Deserialize, Apiv2Schema)]
pub struct Devices {
    /// The devices.
    devices: Vec<Device>,
}

impl Devices {
    /// Register a new device.
    pub fn register(&mut self, device: Device) {
        self.devices.push(device);
    }
}

/// An endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct Device {
    /// Name of the device as configured by the user.
    name: String,
}

/// Get a list of all device endpoints.
#[api_v2_operation]
pub async fn devices(storage: Data<Storage>) -> Result<Json<Devices>> {
    // Get the devices from the database or use the default
    let devices = storage
        .get::<_, Devices>("devices")
        .await?
        .unwrap_or_else(Devices::default);

    Ok(Json(devices))
}

/// Register a new device endpoint.
#[api_v2_operation]
pub async fn register(device: Json<Device>, storage: Data<Storage>) -> Result<CreatedJson<Device>> {
    // Get the devices from the database or use the default
    let mut devices = storage
        .get::<_, Devices>("devices")
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
    use crate::app;
    use actix_storage::Storage;
    use actix_storage_hashmap::HashMapStore;
    use actix_web::{
        http::StatusCode,
        test::{self, TestRequest},
        web::Bytes,
        App,
    };

    #[actix_rt::test]
    async fn test_devices() {
        let mut app = test::init_service(
            App::new()
                .configure(app::router)
                .data(Storage::build().store(HashMapStore::new()).finish()),
        )
        .await;

        // Build a request to test our function
        let req = TestRequest::get()
            .uri("/devices")
            // The peer address must be localhost otherwise the Tor guard triggers
            .peer_addr("127.0.0.1:1234".parse().unwrap())
            .to_request();

        // Perform the request and get the response
        let resp = test::call_service(&mut app, req).await;

        // Ensure that the path is accessed correctly
        assert_eq!(resp.status(), StatusCode::OK);

        // An empty JSON array should be returned
        let bytes = test::read_body(resp).await;
        assert_eq!(bytes, Bytes::from_static(br##"{"devices":[]}"##));
    }
}
