use actix_web::{http::Method, test, App};
use lib::{
    crypto::StaticSecretExt,
    device::{RegisterDevice, RegisterDeviceResult},
};
use x25519_dalek::{PublicKey, StaticSecret};

#[actix_rt::test]
async fn register() {
    // Create the test app with the routes
    let mut app = test::init_service(lib::test::fill_app(App::new())).await;

    // Create a public and a secret key for the device
    let secret_key = StaticSecret::new_with_os_rand();
    let public_key = PublicKey::from(&secret_key);

    // Setup a fake device to register
    let register_device = RegisterDevice::new("test_device", &public_key);

    // Register the device
    let registered: RegisterDeviceResult = lib::test::perform_request_with_body(
        &mut app,
        "/v1/register",
        Method::POST,
        &register_device,
    )
    .await;
    assert_eq!(registered.name, "test_device");
}
