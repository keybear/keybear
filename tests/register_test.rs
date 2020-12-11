use actix_web::App;

#[cfg(feature = "test")]
#[actix_rt::test]
async fn register() {
    // Create the app with the routes
    let app = lib::test::fill_app(App::new());
}
