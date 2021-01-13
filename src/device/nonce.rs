use crate::{app::AppState, body::EncryptedBody};
use actix_web::{
    error::{ErrorBadRequest, ErrorInternalServerError, ErrorNotFound},
    web::{Data, Json},
    Result as WebResult,
};
use keybear_core::crypto::Nonce;
use serde::{Deserialize, Serialize};

/// A simple type to represent a serializable nonce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableNonce([u8; 12]);

impl SerializableNonce {
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
pub async fn nonce() -> WebResult<Json<SerializableNonce>> {
    unimplemented!()
}
