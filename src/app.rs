use crate::{
    config::Config,
    device::{self, Device, Devices},
    net::TorGuard,
    password,
    store::StorageBuilder,
};
use actix_service::ServiceFactory;
use actix_storage::Storage;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    web::{self, Data, ServiceConfig},
    App, Error, Result as WebResult,
};
use anyhow::{anyhow, Result};
use keybear_core::crypto::StaticSecretExt;
use std::sync::Mutex;
use x25519_dalek::StaticSecret;

/// The shareable state of the application.
pub struct AppState {
    /// The database.
    pub storage: Mutex<Storage>,
    /// The secret key to communicate with the clients.
    pub secret_key: StaticSecret,
}

impl AppState {
    /// Construct the application state with the information from the config.
    pub fn from_config(config: &Config) -> Result<Self> {
        // Generate a static secret key if it doesn't exist
        let secret_key = StaticSecret::from_file_or_generate(config.key_path())?;

        // Setup the database
        let storage = Mutex::new(StorageBuilder::new(config.database_path()).build()?);

        Ok(Self {
            secret_key,
            storage,
        })
    }

    /// Set the devices.
    pub async fn set_devices(&self, devices: Devices) -> WebResult<()> {
        // Get a mutex lock on the storage
        let storage = self.storage.lock().unwrap();

        // Persist the devices in the storage
        storage.set("devices", &devices).await?;

        Ok(())
    }

    /// Get the devices from the database.
    pub async fn devices(&self) -> Result<Devices> {
        // Get a mutex lock on the storage
        let storage = self.storage.lock().unwrap();

        // Get the devices from the database or use the default
        Ok(storage
            .get("devices")
            .await
            .map_err(|err| anyhow!("Could not get devices from storage: {}", err))?
            .unwrap_or_else(Devices::default))
    }

    /// Get the device information from the database.
    pub async fn device(&self, device_id: &str) -> Result<Device> {
        // Try to find the device or throw an error when it's not found
        self.devices()
            .await?
            .find(device_id)
            .cloned()
            .ok_or_else(|| anyhow!("Device with ID \"{}\" is not registered", device_id))
    }
}

/// Create the actix app with all routes and services.
pub fn router(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            // This is the only call that's allowed to be done unencrypted
            .service(web::resource("/register").route(web::post().to(device::register)))
            .service(web::resource("/devices").route(web::get().to(device::devices)))
            .service(
                web::resource("/passwords")
                    .route(web::get().to(password::get_passwords))
                    .route(web::post().to(password::post_passwords)),
            )
            .service(web::resource("/passwords/{id}").route(web::get().to(password::get_password)))
            // Ensure that the communication is only going through the Tor service
            .guard(TorGuard),
    );
}

/// Create the server app.
pub fn fill_app<T, B>(app: App<T, B>, app_state: &Data<AppState>) -> App<T, B>
where
    B: MessageBody,
    T: ServiceFactory<
        Config = (),
        Request = ServiceRequest,
        Response = ServiceResponse<B>,
        Error = Error,
        InitError = (),
    >,
{
    app
        // Attach the database
        .app_data(app_state.clone())
        // Configure the routes and services
        .configure(router)
}
