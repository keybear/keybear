use crate::{device, net::TorGuard, password};
use paperclip::actix::web::{self, ServiceConfig};

/// Create the actix app with all routes and services.
pub fn router(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            .service(web::resource("/devices").route(web::get().to(device::devices)))
            .service(web::resource("/register").route(web::post().to(device::register)))
            .service(web::resource("/passwords").route(web::get().to(password::get_passwords)))
            .service(web::resource("/passwords").route(web::post().to(password::post_passwords)))
            .guard(TorGuard),
    );
}
