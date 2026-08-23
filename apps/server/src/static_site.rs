use std::path::{Path, PathBuf};

use actix_files::{Files, NamedFile};
use actix_web::dev::{fn_service, ServiceRequest, ServiceResponse};
use actix_web::HttpResponse;

const INDEX_FILE: &str = "index.html";

/// Serves the exported Expo web app from `static_dir` at the root path.
/// Extension-less paths that match no file fall back to `index.html` so
/// expo-router can resolve them client-side; missing asset paths return 404.
pub fn static_site(static_dir: &str) -> Files {
    let index_path: PathBuf = Path::new(static_dir).join(INDEX_FILE);
    Files::new("/", static_dir)
        .index_file(INDEX_FILE)
        .prefer_utf8(true)
        .default_handler(fn_service(move |req: ServiceRequest| {
            let index_path = index_path.clone();
            async move {
                let (req, _payload) = req.into_parts();
                let response = if is_route_path(req.path()) {
                    NamedFile::open_async(&index_path)
                        .await
                        .map(|file| file.into_response(&req))
                        .unwrap_or_else(|_| HttpResponse::NotFound().finish())
                } else {
                    HttpResponse::NotFound().finish()
                };
                Ok(ServiceResponse::new(req, response))
            }
        }))
}

fn is_route_path(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|segment| !segment.contains('.'))
}
