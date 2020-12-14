use crate::{
    app::AppState,
    crypto::{self, middleware::CLIENT_ID_HEADER},
};
use actix_web::{
    dev::Payload,
    error::{ErrorBadRequest, ErrorInternalServerError, ErrorUnauthorized},
    Error, FromRequest, HttpRequest,
};
use anyhow::Result;
use futures::executor::block_on;
use futures_util::{
    future::{self, Ready},
    StreamExt,
};
use paperclip::{
    actix::{
        web::{Bytes, BytesMut, Data, Json},
        OperationModifier,
    },
    v2::{models::DefaultSchemaRaw, schema::Apiv2Schema},
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::{Deref, DerefMut},
};
use x25519_dalek::SharedSecret;

/// A JSON payload that's encrypted by the client.
pub struct EncryptedJson<T>(pub Json<T>);

impl<T> EncryptedJson<T> {
    /// Construct a new object.
    pub fn new(obj: T) -> Self {
        Self(Json(obj))
    }
}

impl<T> EncryptedJson<T>
where
    T: DeserializeOwned,
{
    /// Deconstruct to an inner value.
    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }

    /// Construct the object from a string value.
    pub fn from_str(raw: &str) -> Result<Self> {
        Ok(Self(Json(serde_json::from_str(raw)?)))
    }
}

impl<T> EncryptedJson<T>
where
    T: Serialize,
{
    /// Serialize it to bytes.
    pub fn to_bytes(self, shared_key: &SharedSecret) -> Result<Bytes> {
        // Serialize the JSON
        let serialized = serde_json::to_string(&self.0 .0)?;

        // Encrypt the serialized part
        let encrypted = crypto::encrypt(shared_key, &serialized)?;

        Ok(Bytes::from(encrypted))
    }
}

impl<T> Deref for EncryptedJson<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for EncryptedJson<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Debug for EncryptedJson<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Encrypted {:?}", self.0)
    }
}

impl<T> Display for EncryptedJson<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

impl<T> FromRequest for EncryptedJson<T>
where
    T: DeserializeOwned + 'static,
{
    type Error = Error;
    type Future = Ready<Result<EncryptedJson<T>, Error>>;
    type Config = ();

    #[inline]
    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
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
            // Throw an error the header is not found
            return future::err(ErrorUnauthorized(format!(
                "\"{}\" header is missing or misformatted",
                CLIENT_ID_HEADER
            )));
        };

        if let Some(state) = req.app_data::<Data<AppState>>() {
            // Clone the secret key because the request will be consumed before it can be used
            let secret_key = state.secret_key.clone();

            // Try to get all the devices from the application state
            // TODO: change this to a proper future instead of block_on
            match block_on(state.devices()) {
                Ok(devices) => {
                    // Find the device matching the ID from the header
                    match devices.find(id) {
                        Some(device) => {
                            // Capture the request body to decrypt it
                            let mut body = BytesMut::new();
                            while let Some(chunk) = block_on(payload.next()) {
                                match chunk {
                                    Ok(chunk) => body.extend_from_slice(&chunk),
                                    Err(err) => {
                                        return future::err(ErrorInternalServerError(format!(
                                            "Could not read chunk from payload: {}",
                                            err
                                        )))
                                    }
                                }
                            }

                            // Decrypt the message contained in the body
                            let message = match device.decrypt(&secret_key, &body) {
                                Ok(message) => message,
                                Err(err) => {
                                    return future::err(ErrorBadRequest(format!(
                                        "Could not decrypt message: {}",
                                        err
                                    )))
                                }
                            };

                            // Try to convert the string to JSON
                            match Self::from_str(&message) {
                                Ok(obj) => future::ok(obj),
                                Err(err) => future::err(ErrorBadRequest(err)),
                            }
                        }
                        None => future::err(ErrorUnauthorized("Device with ID does not exist")),
                    }
                }
                Err(err) => future::err(ErrorInternalServerError(format!(
                    "Could not get devices from application state: {}",
                    err,
                ))),
            }
        } else {
            future::err(ErrorInternalServerError("Application state not set"))
        }
    }
}

// Generate paperclip scheme
impl<T> Apiv2Schema for EncryptedJson<T> {
    const NAME: Option<&'static str> = None;

    fn raw_schema() -> DefaultSchemaRaw {
        Default::default()
    }
}

impl<T> OperationModifier for EncryptedJson<T> where T: Apiv2Schema {}
