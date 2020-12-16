use actix_web::http::Method;
use lib::password::Password;

#[actix_rt::test]
async fn save() {
    // Setup the server and register a single client
    let (mut app, client_id, shared_key) = lib::test::setup_with_client().await;

    // Create a password to save
    let password = Password {
        name: "test".to_string(),
        password: "test_password".to_string(),
        ..Default::default()
    };

    // Save the password
    let created: Password = lib::test::perform_encrypted_request_with_body(
        &mut app,
        "/v1/passwords",
        Method::POST,
        &client_id,
        &shared_key,
        &password,
    )
    .await;
    assert_eq!(password, created);

    // Now verify it's in the list of passwords
    let passwords: Vec<Password> = lib::test::perform_encrypted_request(
        &mut app,
        "/v1/passwords",
        Method::GET,
        &client_id,
        &shared_key,
    )
    .await;
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].name, created.name);
}