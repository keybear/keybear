use crate::{app::AppState, crypto::json::EncryptedJson};
use actix_web::{error::ErrorNotFound, Result};
use paperclip::actix::{
    api_v2_operation,
    web::{Data, Json, Path},
    Apiv2Schema, CreatedJson,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

    /// Get a password by ID.
    pub fn by_id(&self, id: &str) -> Option<&Password> {
        self.passwords.iter().find(|password| password.id == id)
    }
}

/// A password entry.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct RegisterPassword {
    /// Name of the password as configured by the user.
    pub name: String,
    /// The actual password.
    pub password: String,
    /// The e-mail associated.
    pub email: Option<String>,
    /// The website associated.
    pub website: Option<String>,
}

impl RegisterPassword {
    /// Convert this into a password struct that can be added to the database.
    pub fn to_password(&self) -> Password {
        // Generate a new unique identifier
        let id = Uuid::new_v4().to_simple().to_string();

        Password {
            id,
            name: self.name.clone(),
            password: self.password.clone(),
            email: self.email.clone(),
            website: self.website.clone(),
        }
    }
}

/// A password entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub struct Password {
    /// Unique identifier.
    pub id: String,
    /// Name of the password as configured by the user.
    pub name: String,
    /// The actual password.
    pub password: String,
    /// The e-mail associated.
    pub email: Option<String>,
    /// The website associated.
    pub website: Option<String>,
}

/// Get a single password.
#[api_v2_operation]
pub async fn get_password(
    Path((id,)): Path<(String,)>,
    state: Data<AppState>,
) -> Result<Json<Password>> {
    // Get the passwords from the database or use the default
    let passwords = state
        .storage
        .lock()
        .unwrap()
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(Passwords::default);

    // Find the specific password
    match passwords.by_id(&id) {
        Some(password) => Ok(Json(password.clone())),
        None => Err(ErrorNotFound(format!(
            "Password with ID \"{}\" does not exist",
            id
        ))),
    }
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
    password: EncryptedJson<RegisterPassword>,
    state: Data<AppState>,
) -> Result<CreatedJson<Password>> {
    // Get a mutex lock on the storage
    let storage = state.storage.lock().unwrap();

    // Get the passwords from the database or use the default
    let mut passwords = storage
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(Passwords::default);

    // Convert the register password to an internal password used for storage
    let password = password.to_password();

    // Register the passed password
    passwords.register(password.clone());

    // Persist the passwords in the storage
    storage.set("passwords", &passwords).await?;

    Ok(CreatedJson(password))
}
