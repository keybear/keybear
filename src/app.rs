use crate::{
    config::Config,
    crypto::{middleware::Encrypted, StaticSecretExt},
    device,
    device::Devices,
    net::TorGuard,
    password,
    store::StorageBuilder,
};
use actix_storage::Storage;
use actix_web::Result as WebResult;
use anyhow::Result;
use paperclip::actix::web::{self, ServiceConfig};
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
    pub async fn devices(&self) -> WebResult<Devices> {
        // Get a mutex lock on the storage
        let storage = self.storage.lock().unwrap();

        // Get the devices from the database or use the default
        Ok(storage
            .get("devices")
            .await?
            .unwrap_or_else(Devices::default))
    }
}

/// Create the actix app with all routes and services.
pub fn router(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            // This is the only call that's allowed to be done unencrypted
            .service(web::resource("/register").route(web::post().to(device::register)))
            .service(
                web::resource("/devices")
                    .route(web::get().to(device::devices))
                    .wrap(Encrypted::default()),
            )
            .service(
                web::resource("/passwords")
                    .route(web::get().to(password::get_passwords))
                    .wrap(Encrypted::default()),
            )
            .service(
                web::resource("/passwords")
                    .route(web::post().to(password::post_passwords))
                    .wrap(Encrypted::default()),
            )
            // Ensure that the communication is only going through the Tor service
            .guard(TorGuard),
    );
}
