use crate::{
    app::{self, AppState},
    body::EncryptedBody,
};
use actix_http::Request;
use actix_service::ServiceFactory;
use actix_storage::Storage;
use actix_storage_hashmap::HashMapStore;
use actix_web::{
    body::{Body, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse},
    http::Method,
    test::{self, TestRequest},
    web::Data,
    App, Error,
};
use keybear_core::{
    crypto::{self, StaticSecretExt},
    types::{RegisterDeviceRequest, RegisterDeviceResponse},
    CLIENT_ID_HEADER,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, sync::Mutex};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// A client containing the keys to perform test requests.
pub struct TestClient {
    /// The public key of the server.
    pub server_public_key: PublicKey,
    /// The secret key of the client.
    pub client_secret_key: StaticSecret,
    /// The registration ID of the client.
    pub id: String,
}

impl TestClient {
    /// Setup a server with a registered client.
    pub async fn setup() -> (
        impl Service<Request = Request, Response = ServiceResponse<Body>, Error = Error>,
        Self,
    ) {
        // Setup the test service
        let mut app = test::init_service(fill_app(App::new())).await;

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

        // Return the app, the device ID and the device public key
        (
            app,
            Self {
                id: registered.id().to_string(),
                client_secret_key: secret_key,
                server_public_key: registered.server_public_key().unwrap(),
            },
        )
    }

    /// Perform a request without a body and get the result back.
    pub async fn perform_encrypted_request<S, B, E, T>(
        &self,
        app: &mut S,
        path: &str,
        method: Method,
    ) -> T
    where
        S: Service<Request = Request, Response = ServiceResponse<B>, Error = E>,
        B: MessageBody + Unpin,
        E: Debug,
        T: DeserializeOwned,
    {
        // Build a request to test our function
        let req = TestRequest::with_uri(path)
            .header(CLIENT_ID_HEADER, self.id.as_str())
            .method(method)
            // The peer address must be localhost otherwise the Tor guard triggers
            .peer_addr("127.0.0.1:1234".parse().unwrap())
            .to_request();

        // Perform the request and get the response
        let resp = app.call(req).await.unwrap();

        // Ensure that the path is accessed correctly
        assert!(resp.status().is_success());

        // Extract the encrypted body
        let body = test::read_body(resp).await;

        // Decrypt it
        crypto::decrypt(&self.to_shared_secret(), &body).unwrap()
    }

    /// Perform a request with a body and get the result back.
    pub async fn perform_encrypted_request_with_body<S, B, E, J, T>(
        &self,
        app: &mut S,
        path: &str,
        method: Method,
        body: &J,
    ) -> T
    where
        S: Service<Request = Request, Response = ServiceResponse<B>, Error = E>,
        B: MessageBody + Unpin,
        J: Serialize,
        E: Debug,
        T: DeserializeOwned,
    {
        // Create an encrypted JSON payload
        let payload = EncryptedBody::new_with_key(body, self.to_shared_secret())
            .into_bytes()
            .unwrap();

        // Build a request to test our function
        let req = TestRequest::with_uri(path)
            .method(method)
            .header(CLIENT_ID_HEADER, self.id.as_str())
            .set_payload(payload)
            // The peer address must be localhost otherwise the Tor guard triggers
            .peer_addr("127.0.0.1:1234".parse().unwrap())
            .to_request();

        // Perform the request and get the response
        let resp = app.call(req).await.unwrap();

        // Ensure that the path is accessed correctly
        assert!(
            resp.status().is_success(),
            "Incorrect response status \"{}\" with body: {:?}",
            resp.status().canonical_reason().unwrap(),
            test::read_body(resp).await,
        );

        // Extract the encrypted body
        let body = test::read_body(resp).await;

        // Decrypt it
        crypto::decrypt(&self.to_shared_secret(), &body).unwrap()
    }

    /// Generate a shared secret key from the server and client keys.
    pub fn to_shared_secret(&self) -> SharedSecret {
        self.client_secret_key
            .diffie_hellman(&self.server_public_key)
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
        body: &J,
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
            .set_json(body)
            // The peer address must be localhost otherwise the Tor guard triggers
            .peer_addr("127.0.0.1:1234".parse().unwrap())
            .to_request();

        // Perform the request and get the response
        let resp = app.call(req).await.unwrap();

        // Ensure that the path is accessed correctly
        assert!(
            resp.status().is_success(),
            "Response status {} incorrect with body: {:?}",
            resp.status().as_str(),
            test::read_body(resp).await,
        );

        // Extract the JSON response
        test::read_body_json(resp).await
    }
}

/// Generate a default app with all routes.
pub fn fill_app<T, B>(app: App<T, B>) -> App<T, B>
where
    B: MessageBody,
    T: ServiceFactory<
        Config = (),
        Request = ServiceRequest,
        Response = ServiceResponse<B>,
        Error = Error,
        InitError = (),
    >,
{
    app::fill_app(app, &app_state())
}

/// Generate a default application state.
pub fn app_state() -> Data<AppState> {
    Data::new(AppState {
        secret_key: StaticSecret::new_with_os_rand(),
        // Use a simple in-memory hashmap storage
        storage: Mutex::new(Storage::build().store(HashMapStore::default()).finish()),
    })
}
