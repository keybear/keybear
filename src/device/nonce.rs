use crate::app::AppState;
use actix_web::{
    error::{ErrorBadRequest, ErrorInternalServerError},
    web::{Data, Json},
    HttpRequest, Result as WebResult,
};
use keybear_core::{crypto::Nonce, CLIENT_ID_HEADER};
use serde::{Deserialize, Serialize};

/// A simple type to represent a serializable nonce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableNonce([u8; 12]);

impl SerializableNonce {
    /// Generate a new nonce from a series of random bytes.
    pub fn generate() -> Self {
        let random_bytes = rand::random::<[u8; 12]>();

        Self(random_bytes)
    }

    /// Create it from a keybear nonce.
    pub fn from_nonce(nonce: Nonce) -> Self {
        let mut bytes = [0; 12];
        bytes.copy_from_slice(nonce.as_slice());

        Self(bytes)
    }

    /// Convert it to a keybear nonce.
    pub fn to_nonce(&self) -> &Nonce {
        Nonce::from_slice(&self.0)
    }

    /// Convert it to a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Generate a single-use nonce for the device.
pub async fn nonce(
    request: HttpRequest,
    state: Data<AppState>,
) -> WebResult<Json<SerializableNonce>> {
    // First get the client ID header
    match request
        .headers()
        .iter()
        .find(|header| header.0 == CLIENT_ID_HEADER)
    {
        Some((_, client_id_header)) => {
            // Find the device matching the header
            let mut device = state
                .device(client_id_header.to_str().map_err(ErrorBadRequest)?.trim())
                .await
                .map_err(ErrorBadRequest)?;

            // Generate the nonce for the device
            device.generate_nonce();

            // Save the device
            state
                .set_device(&device)
                .await
                .map_err(ErrorInternalServerError)?;

            // Return the nonce as JSON
            Ok(Json(
                device.nonce().map_err(ErrorInternalServerError)?.clone(),
            ))
        }
        None => Err(ErrorBadRequest("Missing client id header")),
    }
}
