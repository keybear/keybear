use crate::{
    device::{self, register},
    net::TorGuard,
    password,
};
use actix_web::web::{self, ServiceConfig};

/// Create the actix app with all routes and services.
pub fn router(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            // This is the only call that's allowed to be done unencrypted
            .service(web::resource("/register").route(web::post().to(register::register)))
            .service(web::resource("/verify").route(web::post().to(register::verify)))
            .service(web::resource("/verification_devices").route(web::get().to(device::devices)))
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
