use crate::{app::AppState, crypto::json::EncryptedJson};
use actix_web::Result;
use paperclip::actix::{
    api_v2_operation,
    web::{Data, Json},
    Apiv2Schema, CreatedJson,
};
use serde::{Deserialize, Serialize};

/// All the passwords.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct Passwords {
    /// The passwords.
    passwords: Vec<Password>,
}

impl Passwords {
    /// Register a new password.
    pub fn register(&mut self, password: Password) {
        self.passwords.push(password);
    }

    /// Get a vector of passwords as allowed to be shown to the clients.
    pub fn to_public_vec(&self) -> Vec<Password> {
        self.passwords.clone()
    }
}

/// A password entry.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct Password {
    /// Name of the password as configured by the user.
    pub name: String,
    /// The actual password.
    pub password: String,
    /// The e-mail associated.
    pub email: Option<String>,
    /// The website associated.
    pub website: Option<String>,
}

/// Get a list of all passwords.
#[api_v2_operation]
pub async fn get_passwords(state: Data<AppState>) -> Result<Json<Vec<Password>>> {
    // Get the passwords from the database or use the default
    let passwords = state
        .storage
        .lock()
        .unwrap()
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(Passwords::default);

    Ok(Json(passwords.to_public_vec()))
}

/// Register a new password.
#[api_v2_operation]
pub async fn post_passwords(
    password: EncryptedJson<Password>,
    state: Data<AppState>,
) -> Result<CreatedJson<Password>> {
    // Get a mutex lock on the storage
    let storage = state.storage.lock().unwrap();

    // Get the passwords from the database or use the default
    let mut passwords = storage
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(Passwords::default);

    // Extract the password from the JSON
    let password = password.into_inner();

    // Register the passed password
    passwords.register(password.clone());

    // Persist the passwords in the storage
    storage.set("passwords", &passwords).await?;

    Ok(CreatedJson(password))
}
