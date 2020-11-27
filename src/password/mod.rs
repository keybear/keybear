use actix_storage::Storage;
use actix_web::{
    get, post,
    web::{Data, Json, Path},
    Error, HttpResponse,
};
use serde::{Deserialize, Serialize};

/// All the passwords.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Passwords {
    /// The passwords.
    passwords: Vec<Password>,
}

impl Passwords {
    /// Register a new password.
    pub fn register(&mut self, password: Password) {
        self.passwords.push(password);
    }
}

/// An endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct Password {
    /// Name of the password as configured by the user.
    name: String,
    /// The actual password.
    password: String,
    /// The e-mail associated.
    email: Option<String>,
    /// The website associated.
    website: Option<String>,
}

/// Get a list of all passwords.
#[get("/passwords")]
pub async fn get_passwords(_path: Path<()>, storage: Data<Storage>) -> Result<HttpResponse, Error> {
    // Get the passwords from the database or use the default
    let passwords = storage
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(|| Passwords::default());

    Ok(HttpResponse::Ok().json(passwords))
}

/// Register a new password.
#[post("/passwords")]
pub async fn post_passwords(
    password: Json<Password>,
    storage: Data<Storage>,
) -> Result<HttpResponse, Error> {
    // Get the passwords from the database or use the default
    let mut passwords = storage
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(|| Passwords::default());

    // Register the passed password
    passwords.register(password.into_inner());

    // Persist the passwords in the storage
    storage.set("passwords", &passwords).await?;

    Ok(HttpResponse::Ok().finish())
}
