use crate::app::AppState;
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

    /// Get the amount of passwords registered.
    pub fn amount(&self) -> usize {
        self.passwords.len()
    }
}

/// A password entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Apiv2Schema)]
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
#[api_v2_operation]
pub async fn get_passwords(state: Data<AppState>) -> Result<Json<Passwords>> {
    // Get the passwords from the database or use the default
    let passwords = state
        .storage
        .lock()
        .unwrap()
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(Passwords::default);

    Ok(Json(passwords))
}

/// Register a new password.
#[api_v2_operation]
pub async fn post_passwords(
    password: Json<Password>,
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

#[cfg(test)]
mod tests {
    use super::{Password, Passwords};
    use actix_web::{http::Method, test, web, App};

    #[actix_rt::test]
    async fn passwords() {
        let mut app = test::init_service(
            App::new()
                .service(web::resource("/passwords").route(web::get().to(super::get_passwords)))
                .app_data(crate::test::app_state()),
        )
        .await;

        // Request the passwords, empty list should be returned
        let passwords: Passwords =
            crate::test::perform_request(&mut app, "/passwords", Method::GET).await;
        assert_eq!(passwords.amount(), 0);
    }

    #[actix_rt::test]
    async fn register() {
        let mut app = test::init_service(
            App::new()
                .service(
                    web::resource("/passwords")
                        .route(web::get().to(super::get_passwords))
                        .route(web::post().to(super::post_passwords)),
                )
                .app_data(crate::test::app_state()),
        )
        .await;

        // Setup a password to get the JSON from
        let password = Password {
            name: "test".to_string(),
            password: "test_password".to_string(),
            email: None,
            website: None,
        };

        // Register the password
        let registered: Password =
            crate::test::perform_request_with_body(&mut app, "/passwords", Method::POST, &password)
                .await;
        assert_eq!(registered, password);

        // Verify that the list of passwords is filled with it
        let passwords: Passwords =
            crate::test::perform_request(&mut app, "/passwords", Method::GET).await;
        assert_eq!(passwords.amount(), 1);
    }
}
