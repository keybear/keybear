use crate::{app::AppState, crypto::StaticSecretExt};
use actix_http::Request;
use actix_storage::Storage;
use actix_storage_hashmap::HashMapStore;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    http::Method,
    test::{self, TestRequest},
    web::Data,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, sync::Mutex};
use x25519_dalek::StaticSecret;

/// Generate a default application state.
pub fn app_state() -> Data<AppState> {
    Data::new(AppState {
        secret_key: StaticSecret::new_with_os_rand(),
        // Use a simple in-memory hashmap storage
        storage: Mutex::new(Storage::build().store(HashMapStore::default()).finish()),
    })
}

/// Perform a request without a body and get the result back.
pub async fn perform_request<S, B, E, T>(app: &mut S, path: &str, method: Method) -> T
where
    S: Service<Request = Request, Response = ServiceResponse<B>, Error = E>,
    B: MessageBody + Unpin,
    E: Debug,
    T: DeserializeOwned,
{
    // Build a request to test our function
    let req = TestRequest::with_uri(path)
        .method(method)
        // The peer address must be localhost otherwise the Tor guard triggers
        .peer_addr("127.0.0.1:1234".parse().unwrap())
        .to_request();

    // Perform the request and get the response
    let resp = app.call(req).await.unwrap();

    // Ensure that the path is accessed correctly
    assert!(resp.status().is_success());

    // Extract the JSON response
    test::read_body_json(resp).await
}

/// Perform a request with a body and get the result back.
pub async fn perform_request_with_body<S, B, E, J, T>(
    app: &mut S,
    path: &str,
    method: Method,
    json_body: &J,
) -> T
where
    S: Service<Request = Request, Response = ServiceResponse<B>, Error = E>,
    B: MessageBody + Unpin,
    J: Serialize,
    E: Debug,
    T: DeserializeOwned,
{
    // Build a request to test our function
    let req = TestRequest::with_uri(path)
        .method(method)
        .set_json(json_body)
        // The peer address must be localhost otherwise the Tor guard triggers
        .peer_addr("127.0.0.1:1234".parse().unwrap())
        .to_request();

    // Perform the request and get the response
    let resp = app.call(req).await.unwrap();

    // Ensure that the path is accessed correctly
    assert!(resp.status().is_success());

    // Extract the JSON response
    test::read_body_json(resp).await
}
