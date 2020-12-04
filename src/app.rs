use crate::{device, net::TorGuard};
use actix_web::web::ServiceConfig;
use paperclip::actix::web;

/// Create the actix app with all routes and services.
pub fn config_app(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/")
            .service(web::resource("/devices").route(web::get().to(device::devices)))
            .service(web::resource("/register").route(web::post().to(device::register)))
            .guard(TorGuard),
    );
}
