use crate::{app::AppState, device::Device};
use actix_http::{h1::Payload as H1Payload, Payload};
use actix_service::{Service, Transform};
use actix_web::{
    body::Body,
    dev::{MessageBody, ResponseBody, ServiceRequest, ServiceResponse},
    error::{ErrorInternalServerError, ErrorUnauthorized},
    Error,
};
use anyhow::{anyhow, Result};
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
use x25519_dalek::StaticSecret;

/// The required HTTP header containing the client ID.
pub const CLIENT_ID_HEADER: &str = "keybear-client-id";

/// Actix middleware for using X25519 encrypted JSON messages.
#[derive(Debug, Default)]
pub struct Encrypted;

impl<S, B> Transform<S> for Encrypted
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + Unpin,
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
    B: MessageBody + Unpin,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        // Clone the service so we can move it to the boxed async block
        let mut service = self.service.clone();

        // First read decrypt the request, then encrypt the response
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

            debug!("Received message from client with ID \"{:?}\"", id);

            if let Some(state) = req.app_data::<Data<AppState>>() {
                // Clone the secret key because the request will be consumed before it can be used
                let secret_key = state.secret_key.clone();

                if let Some(device) = state.devices().await?.find(id) {
                    // Split it into the HTTP request and the payload
                    let (http_request, mut payload) = req.into_parts();

                    // Capture the request body to encrypt it
                    let mut body = BytesMut::new();
                    while let Some(chunk) = payload.next().await {
                        body.extend_from_slice(&chunk?);
                    }

                    // Decrypt the body if applicable and create a new payload
                    let message = if !body.is_empty() {
                        // Decrypt the message contained in the body
                        device
                            .decrypt(&secret_key, &body)
                            .map_err(|err| ErrorUnauthorized(err))?
                    } else {
                        // Use an empty string as the body
                        String::new()
                    };

                    // Construct the payload
                    let payload = {
                        let mut payload = H1Payload::empty();
                        payload.unread_data(body.freeze());

                        Payload::H1(payload)
                    };

                    // Reconstruct the request
                    let req = ServiceRequest::from_parts(http_request, payload)
                        .map_err(|_| ErrorInternalServerError("Cannot reconstruct request"))?;

                    // Handle the request
                    let res = service.call(req).await?;

                    // Encrypt the response
                    Ok(encrypt_response(res, &secret_key, device)
                        .await
                        .map_err(|err| ErrorInternalServerError(err))?)
                } else {
                    // Throw an error when the device can't be verified
                    Err(ErrorUnauthorized("Device has invalid client id"))
                }
            } else {
                // Throw an error when the application state isn't registered yet
                Err(ErrorInternalServerError(
                    "Application state is not registered",
                ))
            }
        })
    }
}

/// Encrypt the response.
async fn encrypt_response<B>(
    mut response: ServiceResponse<B>,
    server_secret_key: &StaticSecret,
    target_device: &Device,
) -> Result<ServiceResponse<B>>
where
    B: MessageBody + Unpin,
{
    // Don't do anything with error messages
    if !response.status().is_success() {
        return Ok(response);
    }

    // Get the body from the response
    let mut body = BytesMut::new();
    let mut stream = response.take_body();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(
            &chunk.map_err(|err| anyhow!("Could not read response body: {}", err))?,
        );
    }
    // Convert the body into a string
    let body_string = String::from_utf8(body.to_vec())?;

    // Encrypt the result
    let result = target_device.encrypt(&server_secret_key, &body_string)?;

    Ok(response.map_body(|_, _| ResponseBody::Other(Body::from(result))))
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::middleware::{Encrypted, CLIENT_ID_HEADER},
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
            .app_data(test::app_state())
            .to_srv_request();
        // This should fail because the device doesn't exist
        assert!(middleware.call(req).await.is_err());
    }
}
