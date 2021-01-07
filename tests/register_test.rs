use actix_web::{http::Method, test, App};
use keybear_core::{
    crypto::StaticSecretExt,
    route::v1,
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

    // Register the device, the first device is always accepted
    let registered: RegisterDeviceResponse = TestClient::perform_request_with_body(
        &mut app,
        &format!("/v1{}", v1::REGISTER),
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

    // Create a public and a secret key for the device
    let secret_key2 = StaticSecret::new_with_os_rand();
    let public_key2 = PublicKey::from(&secret_key2);

    // Setup another fake device to register
    let register_device2 = RegisterDeviceRequest::new("test_device2", &public_key2);

    // Register a new device, this device needs to be verified
    let registered2: RegisterDeviceResponse = TestClient::perform_request_with_body(
        &mut app,
        &format!("/v1{}", v1::REGISTER),
        Method::POST,
        &register_device2,
    )
    .await;
    assert_eq!(registered2.name(), "test_device2");

    // Create another test client from the results
    let client2 = TestClient {
        id: registered2.id().to_string(),
        server_public_key: registered2.server_public_key().unwrap(),
        client_secret_key: secret_key2,
    };

    // Verify this device with the first device
    let verification_device = NeedsVerificationDevice::new(
        registered2.id(),
        registered2.name(),
        registered2.verification_code(),
    );
    let _: () = client
        .perform_encrypted_request_with_body(
            &mut app,
            &format!("/v1{}", v1::VERIFY),
            Method::POST,
            &verification_device,
        )
        .await;

    // Now verify they are both in the list of devices
    // Perform this request from the verified device to ensure that it has proper access
    let devices: Vec<PublicDevice> = client2
        .perform_encrypted_request(&mut app, &format!("/v1{}", v1::DEVICES), Method::GET)
        .await;
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].id(), registered.id());
    assert_eq!(devices[1].id(), registered2.id());
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
        &format!("/v1{}", v1::REGISTER),
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
            &format!("/v1{}", v1::VERIFY),
            Method::POST,
            &verification_device,
        )
        .await;
}
