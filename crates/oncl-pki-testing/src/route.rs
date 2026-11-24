//! Requests routed by URL prefix.

use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use std::sync::Arc;

/// An [`HttpTransport`] that hands each request to the first transport whose URL prefix the
/// request URL starts with; a URL no prefix matches gets `HttpError::other("no route")`.
pub struct RouteTransport {
    routes: Vec<(String, Arc<dyn HttpTransport>)>,
}

impl RouteTransport {
    /// Routes `(URL prefix, transport)`, tried in order.
    pub fn new(routes: Vec<(String, Arc<dyn HttpTransport>)>) -> Self {
        RouteTransport { routes }
    }
}

impl HttpTransport for RouteTransport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.routes
            .iter()
            .find(|(prefix, _)| request.url.starts_with(prefix.as_str()))
            .map(|(_, transport)| transport.as_ref())
            .ok_or_else(|| HttpError::other("no route"))?
            .send(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::http::GetOptions;

    /// Answers its status, with the request's size limit as the content type.
    struct Fixed(u16);

    impl HttpTransport for Fixed {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            Ok(HttpReply {
                status: self.0,
                content_type: Some(request.opts.max_len.to_string()),
                location: None,
                body: Vec::new(),
            })
        }
    }

    #[test]
    fn the_first_matching_prefix_answers() {
        let routes = RouteTransport::new(vec![
            ("http://a.test/x".to_owned(), Arc::new(Fixed(201)) as _),
            ("http://a.test".to_owned(), Arc::new(Fixed(202)) as _),
        ]);
        let status = |url| routes.get(url).map(|r| r.status);
        assert_eq!(status("http://a.test/x/1"), Ok(201));
        assert_eq!(status("http://a.test/y"), Ok(202));
        assert_eq!(
            routes.post("http://a.test/x", "t", b"").map(|r| r.status),
            Ok(201)
        );
        let opts = GetOptions {
            max_len: 7,
            ..GetOptions::default()
        };
        assert_eq!(
            routes
                .get_with("http://a.test/y", opts)
                .map(|r| r.content_type),
            Ok(Some("7".to_owned()))
        );
        assert_eq!(status("http://b.test"), Err(HttpError::other("no route")));
    }
}
