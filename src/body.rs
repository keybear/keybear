use crate::app::AppState;
use actix_web::{
    dev::Payload,
    error::{ErrorInternalServerError, ErrorUnauthorized},
    web::{Bytes, BytesMut, Data},
    Error, FromRequest, HttpRequest, HttpResponse, Responder,
};
use anyhow::{anyhow, bail, Result};
use futures::{executor::block_on, Future};
use futures_util::{
    future::{self, Ready},
    FutureExt, StreamExt,
};
use keybear_core::{crypto, CLIENT_ID_HEADER};
use log::debug;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::{Deref, DerefMut},
    pin::Pin,
};
use x25519_dalek::SharedSecret;

/// A payload that's encrypted by the client.
pub struct EncryptedBody<T> {
    /// The serializable payload.
    data: T,
    /// The shared key to encrypt the message.
    ///
    /// For decryption it's not required that this has a value.
    /// The value will be filled by the HTTP request.
    key: Option<SharedSecret>,
    /// The client identifier.
    ///
    /// For decryption it's not required that this has a value.
    /// The value will be filled by the HTTP request.
    client_id: Option<String>,
}

impl<T> EncryptedBody<T> {
    /// Construct a new object without a key.
    pub fn new(data: T) -> Self {
        Self {
            data,
            key: None,
            client_id: None,
        }
    }

    /// Construct a new object with a key.
    pub fn new_with_key_and_client_id<S>(data: T, key: SharedSecret, client_id: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            data,
            key: Some(key),
            client_id: Some(client_id.into()),
        }
    }

    /// Get the client ID, can only be retrieved from requests.
    pub fn client_id(&self) -> Result<&str> {
        self.client_id
            .as_deref()
            .ok_or_else(|| anyhow!("Client ID not set on encrypted body"))
    }
}

impl<T> EncryptedBody<T>
where
    T: DeserializeOwned,
{
    /// Deconstruct to an inner value.
    pub fn into_inner(self) -> T {
        self.data
    }

    /// Deconstruct to an inner value with the ID attached.
    pub fn into_inner_with_client_id(self) -> Result<(T, String)> {
        Ok((
            self.data,
            self.client_id
                .ok_or_else(|| anyhow!("Client ID not set on encrypted body"))?,
        ))
    }
}

impl<T> EncryptedBody<T>
where
    T: Serialize,
{
    /// Encrypt a request body.
    async fn encrypt_request(&self, id: &str, state: &AppState) -> Result<Vec<u8>> {
        // Find the device from the ID
        let device = state.device(id).await?;

        device.encrypt(&state.secret_key, &self.data)
    }

    /// Serialize it to bytes.
    pub fn into_bytes(self) -> Result<Bytes> {
        match self.key {
            Some(key) => {
                // Encrypt the object
                let encrypted = crypto::encrypt(&key, &self.data)?;

                Ok(Bytes::from(encrypted))
            }
            None => bail!("Encryption key not set"),
        }
    }
}

impl<T> Deref for EncryptedBody<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.data
    }
}

impl<T> DerefMut for EncryptedBody<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T> Debug for EncryptedBody<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Encrypted {:?}", self.data)
    }
}

impl<T> Display for EncryptedBody<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.data, f)
    }
}

impl<T> FromRequest for EncryptedBody<T>
where
    T: DeserializeOwned + 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>> + 'static>>;
    type Config = ();

    #[inline]
    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // Clone the request so it can be sent to the async block
        let req = req.clone();

        // Take the payload so it can be send to the async block
        let mut payload = payload.take();

        // Try to decrypt the request
        async move {
            debug!("Received encrypted request to path \"{}\"", req.path());

            // Get the app state and the client ID from the request
            let (id, state) = request_id_and_app_state(&req).map_err(ErrorUnauthorized)?;

            debug!("Found matching client from request");

            // Capture the request body to decrypt it
            let mut body = BytesMut::new();
            while let Some(chunk) = payload.next().await {
                body.extend_from_slice(&chunk?);
            }

            debug!("Received body payload of {} bytes", body.len());

            // Find the device from the ID
            let device = state.device(&id).await.map_err(ErrorUnauthorized)?;

            // Decrypt the message contained in the body
            let data = device
                .decrypt(&state.secret_key, &body)
                .map_err(ErrorInternalServerError)?;

            // Get a shared key from the device, this will be passed so an encrypted response can
            // be sent back
            let shared_key = device.shared_key(&state.secret_key);

            Ok(Self {
                data,
                key: Some(shared_key),
                client_id: Some(id),
            })
        }
        .boxed_local()
    }
}

impl<T> Responder for EncryptedBody<T>
where
    T: Serialize,
{
    type Error = Error;
    type Future = Ready<Result<HttpResponse, Error>>;

    fn respond_to(self, req: &HttpRequest) -> Self::Future {
        // Get the app state and the client ID from the request
        let (id, state) = match request_id_and_app_state(req) {
            Ok(ok) => ok,
            Err(err) => return future::err(ErrorUnauthorized(err)),
        };

        // Encrypt the body
        match block_on(self.encrypt_request(&id, state)) {
            Ok(body) => future::ready(Ok(HttpResponse::Ok().body(body))),
            Err(err) => future::err(ErrorInternalServerError(err)),
        }
    }
}

/// Get the requesting client ID and the app state object reference from an HTTP request.
fn request_id_and_app_state(req: &HttpRequest) -> Result<(String, &AppState)> {
    let headers = req.headers();

    // Try to find the client ID header
    let id = if let Some(id) = headers.iter().find_map(|(name, value)| {
        if name == CLIENT_ID_HEADER {
            value.to_str().ok()
        } else {
            None
        }
    }) {
        id
    } else {
        bail!("\"{}\" header is missing or misformatted", CLIENT_ID_HEADER);
    };

    Ok((
        id.to_string(),
        req.app_data::<Data<AppState>>()
            .ok_or_else(|| anyhow!("Could not get application state from request"))?,
    ))
}
