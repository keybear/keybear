use actix_storage::Storage;
use actix_web::{
    get, post,
    web::{Data, Json, Path},
    Error, HttpResponse,
};
use serde::{Deserialize, Serialize};

/// A list of endpoints.
#[derive(Debug, Default, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    /// Name of the device as configured by the user.
    name: String,
}

/// Get a list of all endpoints.
#[get("/devices")]
pub async fn get_devices(_path: Path<()>, storage: Data<Storage>) -> Result<HttpResponse, Error> {
    // Get the devices from the database or use the default
    let devices = storage
        .get::<_, Devices>("devices")
        .await?
        .unwrap_or_else(|| Devices::default());

    Ok(HttpResponse::Ok().json(devices))
}

/// Register a new endpoint.
#[post("/devices")]
pub async fn post_devices(
    device: Json<Device>,
    storage: Data<Storage>,
) -> Result<HttpResponse, Error> {
    // Get the devices from the database or use the default
    let mut devices = storage
        .get::<_, Devices>("devices")
        .await?
        .unwrap_or_else(|| Devices::default());

    // Register the passed device
    devices.register(device.into_inner());

    // Persist the devices in the storage
    storage.set("devices", &devices).await?;

    Ok(HttpResponse::Ok().finish())
}
