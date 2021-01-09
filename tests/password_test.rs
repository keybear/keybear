use actix_web::http::Method;
use keybear_core::{
    route::v1,
    types::{PasswordResponse, PublicPassword, RegisterPasswordRequest},
};
use lib::test::TestClient;

#[actix_rt::test]
async fn save() {
    // Setup the server and register a single client
    let (mut app, client) = TestClient::setup().await;

    // Create a password to save
    let password =
        RegisterPasswordRequest::new::<_, _, String, String>("test", "test_password", None, None);

    // Save the password
    let created: PublicPassword = client
        .perform_encrypted_request_with_body(&mut app, v1::PASSWORD, Method::POST, &password)
        .await;
    assert_eq!(password.name(), created.name());

    // Verify it's in the list of passwords
    let passwords: Vec<PublicPassword> = client
        .perform_encrypted_request(&mut app, v1::PASSWORD, Method::GET)
        .await;
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].id(), created.id());

    // Try to get the password by it's ID
    let stored_password: PasswordResponse = client
        .perform_encrypted_request(
            &mut app,
            &format!("{}/{}", v1::PASSWORD, created.id()),
            Method::GET,
        )
        .await;
    assert_eq!(stored_password.password(), password.password());
}
