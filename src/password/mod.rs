use crate::{app::AppState, body::EncryptedBody};
use actix_web::{
    error::ErrorNotFound,
    web::{Data, Path},
    Result,
};
use keybear_core::types::{PasswordResponse, PublicPassword, RegisterPasswordRequest};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Allow converting an incoming message to a device.
trait ToPassword {
    fn to_password(&self) -> Password;
}

/// All the passwords.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
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
    pub fn to_public_vec(&self) -> Vec<PublicPassword> {
        self.passwords.iter().map(|pass| pass.to_public()).collect()
    }

    /// Get a password by ID.
    pub fn by_id(&self, id: &str) -> Option<&Password> {
        self.passwords.iter().find(|password| password.id == id)
    }
}

impl ToPassword for RegisterPasswordRequest {
    /// Convert this into a password struct that can be added to the database.
    fn to_password(&self) -> Password {
        // Generate a new unique identifier
        let id = Uuid::new_v4().to_simple().to_string();

        Password {
            id,
            name: self.name().to_string(),
            password: self.password().to_string(),
            email: self.email().map(|s| s.to_string()),
            website: self.website().map(|s| s.to_string()),
        }
    }
}

/// A password entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl Password {
    /// Convert it to a message response.
    pub fn to_response(&self) -> PasswordResponse {
        PasswordResponse::new(&self.password)
    }

    /// Convert it to a public password, without the actual password.
    pub fn to_public(&self) -> PublicPassword {
        PublicPassword::new(
            &self.id,
            &self.name,
            self.email.as_ref(),
            self.website.as_ref(),
        )
    }
}

/// Get a single password.
pub async fn get_password(
    Path((id,)): Path<(String,)>,
    state: Data<AppState>,
) -> Result<EncryptedBody<PasswordResponse>> {
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
        Some(password) => Ok(EncryptedBody::new(password.to_response())),
        None => Err(ErrorNotFound(format!(
            "Password with ID \"{}\" does not exist",
            id
        ))),
    }
}

/// Get a list of all passwords.
pub async fn get_passwords(state: Data<AppState>) -> Result<EncryptedBody<Vec<PublicPassword>>> {
    // Get the passwords from the database or use the default
    let passwords = state
        .storage
        .lock()
        .unwrap()
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(Passwords::default);

    Ok(EncryptedBody::new(passwords.to_public_vec()))
}

/// Register a new password.
pub async fn post_passwords(
    password: EncryptedBody<RegisterPasswordRequest>,
    state: Data<AppState>,
) -> Result<EncryptedBody<PublicPassword>> {
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

    Ok(EncryptedBody::new(password.to_public()))
}
