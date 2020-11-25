use actix_storage::Storage;
use actix_web::{
    get,
    web::{Data, Json, Path},
    HttpResponse, Responder,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// An user endpoint.
#[derive(Serialize, Deserialize)]
pub struct Device {
    /// Name of the device as configured by the user.
    name: String,
}

/// Get a list of all users.
#[get("/devices")]
pub async fn devices(_path: Path<()>, storage: Data<Storage>) -> Result<Json<Vec<Device>>> {
    let devices = storage.get::<_, Device>().await?;

    Ok(Json(devices))
}
