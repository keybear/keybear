use actix_web::http::Method;
use keybear_core::{route::v1, types::PublicPassword};
use lib::test::TestClient;

#[actix_rt::test]
async fn nonce() {
    // Setup the server and register a single client
    let (mut app, client) = TestClient::setup().await;

    // Perform a request to get a nonce
    client.perform_nonce_request(&mut app).await.unwrap();
}

#[actix_rt::test]
#[should_panic]
async fn request_without_nonce() {
    // Setup the server and register a single client
    let (mut app, client) = TestClient::setup().await;

    // Do a request without a nonce request, this should fail
    client
        .perform_encrypted_request_without_nonce(&mut app, v1::PASSWORD, Method::GET)
        .await;
}

#[actix_rt::test]
#[should_panic]
async fn request_reset_nonce() {
    // Setup the server and register a single client
    let (mut app, client) = TestClient::setup().await;

    // Do a request that will set the nonce only for this request, it should be cleared after this
    let _: Vec<PublicPassword> = client
        .perform_encrypted_request(&mut app, v1::PASSWORD, Method::GET)
        .await;

    // Do a request without a nonce request, this should fail
    client
        .perform_encrypted_request_without_nonce(&mut app, v1::PASSWORD, Method::GET)
        .await;
}
