use crate::{
    device::{self, nonce, register},
    net::TorGuard,
    password,
};
use actix_web::web::{self, ServiceConfig};
use keybear_core::route::v1;

/// Create the actix app with all routes and services.
pub fn router(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/")
            // Unencrypted calls
            .service(web::resource(v1::REGISTER).route(web::post().to(register::register)))
            .service(web::resource(v1::NONCE).route(web::post().to(nonce::nonce)))
            // Encrypted calls
            .service(web::resource(v1::VERIFY).route(web::post().to(register::verify)))
            .service(
                web::resource(v1::VERIFICATION_DEVICES)
                    .route(web::get().to(register::verification_devices)),
            )
            .service(web::resource(v1::DEVICES).route(web::get().to(device::devices)))
            .service(
                web::resource(v1::PASSWORD)
                    .route(web::get().to(password::get_passwords))
                    .route(web::post().to(password::post_passwords)),
            )
            .service(
                web::resource(format!("{}/{{id}}", v1::PASSWORD))
                    .route(web::get().to(password::get_password)),
            )
            // Ensure that the communication is only going through the Tor service
            .guard(TorGuard),
    );
}
