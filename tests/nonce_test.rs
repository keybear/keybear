use lib::test::TestClient;

#[actix_rt::test]
async fn nonce() {
    // Setup the server and register a single client
    let (_app, _client) = TestClient::setup().await;

    // TODO: fill this unit test
}
