use actix_web::{http::Method, test, App};
use keybear_core::{
    crypto::StaticSecretExt,
    types::{NeedsVerificationDevice, PublicDevice, RegisterDeviceRequest, RegisterDeviceResponse},
};
use lib::test::TestClient;
use x25519_dalek::{PublicKey, StaticSecret};

#[actix_rt::test]
async fn register() {
    // Create the test app with the routes
    let mut app = test::init_service(lib::test::fill_app(App::new())).await;

    // Create a public and a secret key for the device
    let secret_key = StaticSecret::new_with_os_rand();
    let public_key = PublicKey::from(&secret_key);

    // Setup a fake device to register
    let register_device = RegisterDeviceRequest::new("test_device", &public_key);

    // Register the device
    let registered: RegisterDeviceResponse = TestClient::perform_request_with_body(
        &mut app,
        "/v1/register",
        Method::POST,
        &register_device,
    )
    .await;
    assert_eq!(registered.name(), "test_device");

    // Create a test client from the results
    let client = TestClient {
        id: registered.id().to_string(),
        server_public_key: registered.server_public_key().unwrap(),
        client_secret_key: secret_key,
    };

    // Now verify it's in the list of devices
    let devices: Vec<PublicDevice> = client
        .perform_encrypted_request(&mut app, "/v1/devices", Method::GET)
        .await;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id(), registered.id());
}

#[actix_rt::test]
#[should_panic]
async fn illegal_verify() {
    // Create the test app with the routes
    let mut app = test::init_service(lib::test::fill_app(App::new())).await;

    // Create a public and a secret key for the device
    let secret_key = StaticSecret::new_with_os_rand();
    let public_key = PublicKey::from(&secret_key);

    // Setup a fake device to register
    let register_device = RegisterDeviceRequest::new("test_device", &public_key);

    // Register the device
    let registered: RegisterDeviceResponse = TestClient::perform_request_with_body(
        &mut app,
        "/v1/register",
        Method::POST,
        &register_device,
    )
    .await;
    assert_eq!(registered.name(), "test_device");

    // Create a test client from the results
    let client = TestClient {
        id: registered.id().to_string(),
        server_public_key: registered.server_public_key().unwrap(),
        client_secret_key: secret_key,
    };

    // Try to verify with the device we are registering with, which is illegal
    let verification_device = NeedsVerificationDevice::new(
        registered.id(),
        registered.name(),
        registered.verification_code(),
    );
    let _: () = client
        .perform_encrypted_request_with_body(
            &mut app,
            "v1/verify",
            Method::POST,
            &verification_device,
        )
        .await;
}
