use crate::app::AppState;
use actix_service::{Service, Transform};
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    error::{ErrorInternalServerError, ErrorUnauthorized},
    Error, HttpMessage,
};
use futures::{
    future::{ok, Ready},
    stream::StreamExt,
    Future,
};
use log::debug;
use paperclip::actix::web::{BytesMut, Data};
use std::{
    cell::RefCell,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

/// The required HTTP header containing the client ID.
const CLIENT_ID_HEADER: &str = "keybear-client-id";
/// The required HTTP header containing the client verification, encrypted using the shared key.
const CLIENT_VERIFICATION_HEADER: &str = "keybear-client-verification";

/// Actix middleware for using X25519 encrypted JSON messages.
#[derive(Debug, Default)]
pub struct Encrypted;

impl<S, B> Transform<S> for Encrypted
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = EncryptedMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(EncryptedMiddleware {
            service: Rc::new(RefCell::new(service)),
        })
    }
}

/// The middleware that will be automatically constructed by actix using the transform above.
#[doc(hidden)]
#[derive(Debug)]
pub struct EncryptedMiddleware<S> {
    // Reference count it to avoid lifetime issues
    service: Rc<RefCell<S>>,
}

impl<S, B> Service for EncryptedMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, mut req: ServiceRequest) -> Self::Future {
        // Clone the service so we can move it to the boxed async block
        let mut service = self.service.clone();

        // Handle the response
        Box::pin(async move {
            let headers = req.headers();

            // Try to find the client ID header
            let id = if let Some(id) = headers.iter().find_map(|(name, value)| {
                if name == CLIENT_ID_HEADER {
                    value.to_str().ok()
                } else {
                    None
                }
            }) {
                id
            } else {
                // Throw an error the header is not found
                return Err(ErrorUnauthorized(format!(
                    "\"{}\" header is missing or misformatted",
                    CLIENT_ID_HEADER
                )));
            };

            // Try to find the client verification header
            let verification = if let Some(verification) =
                headers.iter().find_map(|(name, value)| {
                    if name == CLIENT_VERIFICATION_HEADER {
                        value.to_str().ok()
                    } else {
                        None
                    }
                }) {
                verification
            } else {
                // Throw an error the header is not found
                return Err(ErrorUnauthorized(format!(
                    "\"{}\" header is missing or misformatted",
                    CLIENT_VERIFICATION_HEADER
                )));
            };

            debug!("Received message from client with ID \"{:?}\"", id);

            // Verify the request
            if let Some(state) = req.app_data::<Data<AppState>>() {
                if !state.devices().await?.verify(id, verification) {
                    // Throw an error when the device can't be verified
                    return Err(ErrorUnauthorized("Device verification failed"));
                }
            } else {
                // Throw an error when the application state isn't registered yet
                return Err(ErrorInternalServerError(
                    "Application state is not registered",
                ));
            };

            // Capture the request body to encrypt it
            let mut body = BytesMut::new();
            let mut stream = req.take_payload();
            while let Some(chunk) = stream.next().await {
                body.extend_from_slice(&chunk?);
            }

            // Encrypt the body if applicable
            if !body.is_empty() {
                dbg!(body);
            }

            // Handle the request
            let res = service.call(req).await?;

            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::middleware::{Encrypted, CLIENT_ID_HEADER, CLIENT_VERIFICATION_HEADER},
        test,
    };
    use actix_service::{Service, Transform};
    use actix_web::test::{ok_service, TestRequest};

    #[actix_rt::test]
    async fn errors() {
        // Setup the encryption middleware
        let mut middleware = Encrypted::default()
            .new_transform(ok_service())
            .await
            .unwrap();

        // Fake an empty request
        let req = TestRequest::default()
            .app_data(test::app_state())
            .to_srv_request();
        // This should fail because the required headers are missing
        assert!(middleware.call(req).await.is_err());

        // Add the proper headers
        let req = TestRequest::default()
            .header(CLIENT_ID_HEADER, "test")
            .header(CLIENT_VERIFICATION_HEADER, "keybear")
            .app_data(test::app_state())
            .to_srv_request();
        // This should fail because the device doesn't exist
        assert!(middleware.call(req).await.is_err());
    }
}
