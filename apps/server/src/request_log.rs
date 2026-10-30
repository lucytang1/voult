//! Query-free HTTP access log.
//!
//! Actix's stock `Logger` logs the request line with `%r`, which includes the
//! query string, and the default format also logs `Referer` and `User-Agent`.
//! For Voult those are not safe defaults: the query carries vault ids, favicon
//! site URLs, OAuth authorization codes, and OAuth state, and the Referer of a
//! request that follows an OAuth return carries the same values again. See
//! `plans/p0-log-redaction.md`.
//!
//! This middleware logs only what is safe to keep forever:
//!
//! ```text
//! GET /api/cloud/oauth/callback 302 {
//!   duration_ms: 12
//! }
//! ```
//!
//! The path comes from Actix's route table (`match_pattern`), not from the
//! request target, so a matched path-param route logs its template
//! (`/api/x/{id}`) and never the value. Unmatched `/api` requests log
//! `unmatched`; static-site requests log `static`. There is deliberately no
//! client IP, header, size, or body field: those are either personal data or
//! attacker-controlled, and none of them are needed to answer "which route,
//! what status, how slow".
//!
//! Do not reintroduce Actix's stock request logger: its `%r` is the exact
//! leak this module replaces.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Instant;

use actix_web::Error;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};

use logger::{Logger, ServerContext, ServerLogger};

const LOG: ServerLogger = Logger::create(ServerContext::Request);

/// App-wide access-log middleware. Install once, as the outermost `wrap`, so
/// requests rejected by CORS or left as unhandled errors are still accounted
/// for.
#[derive(Clone, Copy, Default)]
pub struct RequestLog;

/// The label that replaces the raw request path.
///
/// `pattern` is Actix's declared route pattern. It is either the literal
/// resource path (`/api/favicon`), a template (`/api/x/{id}`), or `""` for a
/// service such as `actix_files::Files` (verified in a scratch Actix app: the
/// static site reports `Some("")`, not `None`). Treating the empty string as
/// "no pattern" is what makes `/vault` log as `static` instead of an empty
/// field.
///
/// `path` is used only to distinguish an unmatched API route from a static
/// path. It is stripped at `?`/`#` defensively, so even a caller that passes a
/// full request target cannot leak a query; the function signature also makes
/// the query unavailable to the normal call site.
pub(crate) fn label<'a>(pattern: Option<&'a str>, path: &str) -> &'a str {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    match pattern {
        Some(pattern) if !pattern.is_empty() => pattern,
        _ if path.starts_with("/api") => "unmatched",
        _ => "static",
    }
}

/// The single access-log line format. Kept separate from the middleware so it
/// is unit-testable without a logger sink.
pub(crate) fn line(method: &str, label: &str, status: u16) -> String {
    format!("{method} {label} {status}")
}

impl<S, B> Transform<S, ServiceRequest> for RequestLog
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestLogMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLogMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct RequestLogMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestLogMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let started = Instant::now();
        let method = req.method().as_str().to_string();
        let pattern = req.match_pattern();
        let label = label(pattern.as_deref(), req.path()).to_string();
        let service = self.service.clone();

        Box::pin(async move {
            let result = service.call(req).await;
            let duration_ms = started.elapsed().as_millis() as u64;

            match result {
                Ok(res) => {
                    LOG.log(
                        line(&method, &label, res.status().as_u16()),
                        logger::metadata! { "duration_ms" => duration_ms },
                    );
                    Ok(res)
                }
                Err(err) => {
                    // Actix converts an unhandled middleware/handler error to a
                    // 500 after this layer, so record the status the client
                    // will actually see and mark it as not produced by a
                    // handler.
                    LOG.warn(
                        line(&method, &label, 500),
                        logger::metadata! {
                            "duration_ms" => duration_ms,
                            "unhandled" => true,
                        },
                    );
                    Err(err)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_declared_route_pattern() {
        assert_eq!(label(Some("/api/favicon"), "/api/favicon"), "/api/favicon");
        assert_eq!(
            label(Some("/api/vaults/{id}"), "/api/vaults/abc"),
            "/api/vaults/{id}"
        );
    }

    #[test]
    fn treats_an_empty_pattern_as_missing() {
        // actix_files::Files reports Some("") for the static site.
        assert_eq!(label(Some(""), "/vault"), "static");
        assert_eq!(label(Some(""), "/"), "static");
    }

    #[test]
    fn labels_unmatched_api_and_static_paths() {
        assert_eq!(label(None, "/api/nope"), "unmatched");
        assert_eq!(label(None, "/api"), "unmatched");
        assert_eq!(label(None, "/vault"), "static");
    }

    #[test]
    fn never_includes_a_query() {
        assert_eq!(label(None, "/api/nope?secret=1"), "unmatched");
        assert_eq!(label(Some("/api/x"), "/api/x?secret=1"), "/api/x");
        assert_eq!(label(None, "/vault?cloud_state=SECRET"), "static");
    }

    #[test]
    fn builds_a_query_free_line() {
        assert_eq!(line("GET", "/api/x", 200), "GET /api/x 200");
        assert!(!line("GET", "/api/x", 200).contains('?'));
    }

    #[actix_web::test]
    async fn passes_the_response_through_unchanged() {
        use actix_web::{App, test, web};

        let app = test::init_service(
            App::new()
                .wrap(RequestLog)
                .route("/x", web::get().to(|| async { "ok" })),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/x?secret=1").to_request(),
        )
        .await;

        assert!(response.status().is_success());
    }
}
