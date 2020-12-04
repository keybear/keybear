use actix_storage::Storage;
use actix_web::Result;
use paperclip::actix::{
    api_v2_operation,
    web::{Data, Json},
    Apiv2Schema, CreatedJson,
};
use serde::{Deserialize, Serialize};

/// All the passwords.
#[derive(Debug, Default, Serialize, Deserialize, Apiv2Schema)]
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

/// A password entry.
#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
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
pub async fn get_passwords(storage: Data<Storage>) -> Result<Json<Passwords>> {
    // Get the passwords from the database or use the default
    let passwords = storage
        .get::<_, Passwords>("passwords")
        .await?
        .unwrap_or_else(Passwords::default);

    Ok(Json(passwords))
}

/// Register a new password.
#[api_v2_operation]
pub async fn post_passwords(
    password: Json<Password>,
    storage: Data<Storage>,
) -> Result<CreatedJson<Password>> {
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
    use actix_storage::Storage;
    use actix_storage_hashmap::HashMapStore;
    use actix_web::{
        http::StatusCode,
        test::{self, TestRequest},
        web::{self, Bytes},
        App,
    };

    #[actix_rt::test]
    async fn test_devices() {
        let mut app = test::init_service(
            App::new()
                .service(web::resource("/passwords").route(web::get().to(super::get_passwords)))
                .data(Storage::build().store(HashMapStore::new()).finish()),
        )
        .await;

        // Build a request to test our function
        let req = TestRequest::get()
            .uri("/passwords")
            // The peer address must be localhost otherwise the Tor guard triggers
            .peer_addr("127.0.0.1:1234".parse().unwrap())
            .to_request();

        // Perform the request and get the response
        let resp = test::call_service(&mut app, req).await;

        // Ensure that the path is accessed correctly
        assert_eq!(resp.status(), StatusCode::OK);

        // An empty JSON array should be returned
        let bytes = test::read_body(resp).await;
        assert_eq!(bytes, Bytes::from_static(br##"{"passwords":[]}"##));
    }
}
