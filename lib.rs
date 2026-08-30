use js_sys::Uint8Array;
use url::Url;
use wasm_bindgen::JsValue;
use worker::*;

/// MIME type required by the DNS-over-HTTPS wire format (RFC 8484).
const DNS_MIME: &str = "application/dns-message";

/// UPSTREAM DoH ENDPOINT CONFIGURATION
/// Change this URL to your preferred DNS-over-HTTPS provider.
const UPSTREAM_DOH_ENDPOINT: &str = "https://family.dns.mullvad.net/dns-query";

/// CUSTOM PATH CONFIGURATION
/// Change this to whatever path you want your DNS to listen on.
/// Highly recommended to use a specific path to block unauthorized bot traffic.
const DNS_PATH: &str = "/dns-query";

#[event(fetch)]
async fn fetch(mut req: Request, _env: Env, ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let method = req.method();

    // Path filter: drop random scanner bots instantly to protect your daily request quota.
    if url.path() != DNS_PATH {
        let origin = url.origin().ascii_serialization();
        return Response::error(
            format!("DoH Proxy is active. Route queries through: {origin}{DNS_PATH}"),
            404,
        );
    }

    // Instant CORS preflight response.
    if method == Method::Options {
        let mut headers = Headers::new();
        headers.set("Access-Control-Allow-Origin", "*")?;
        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
        headers.set("Access-Control-Allow-Headers", "Content-Type, Accept")?;
        headers.set("Access-Control-Max-Age", "86400")?;
        return Ok(Response::empty()?.with_headers(headers));
    }

    let is_get = method == Method::Get;
    let cache = Cache::default();

    // Serve from Cloudflare's edge cache if available.
    if is_get {
        if let Some(cached) = cache.get(&req, false).await? {
            return Ok(cached);
        }
    }

    // Build the upstream target URL, forwarding the query string (?dns=... on GET).
    let mut target_url =
        Url::parse(UPSTREAM_DOH_ENDPOINT).expect("UPSTREAM_DOH_ENDPOINT must be a valid URL");
    target_url.set_query(url.query());

    let mut upstream_headers = Headers::new();
    upstream_headers.set("Accept", DNS_MIME)?;
    upstream_headers.set("Content-Type", DNS_MIME)?;
    upstream_headers.set("User-Agent", "DoH-Edge/3.0-rs")?;

    let mut init = RequestInit::new();
    init.with_method(method.clone());
    init.with_headers(upstream_headers);

    // NOTE: unlike the JS version, we can't hand the incoming ReadableStream
    // straight through to the outbound fetch — we buffer it instead. DoH POST
    // bodies are a single DNS wire-format packet (usually well under 4KB), so
    // this buffering is effectively free in practice.
    if method == Method::Post {
        let body = req.bytes().await?;
        let js_body: JsValue = Uint8Array::from(body.as_slice()).into();
        init.with_body(Some(js_body));
    }

    let upstream_req = Request::new_with_init(target_url.as_str(), &init)?;

    let mut upstream_resp = match Fetch::Request(upstream_req).send().await {
        Ok(resp) => resp,
        Err(e) => return Response::error(format!("DNS Bridge Error: {e}"), 502),
    };

    let status = upstream_resp.status_code();
    let ok = (200..300).contains(&status);
    let body = upstream_resp.bytes().await?;

    let mut out_headers = upstream_resp.headers().clone();
    out_headers.set("Access-Control-Allow-Origin", "*")?;
    if is_get && ok {
        out_headers.set("Cache-Control", "public, max-age=60")?;
    }

    let mut response = Response::from_bytes(body)?
        .with_status(status)
        .with_headers(out_headers);

    // Save to cache asynchronously in the background without making the client wait.
    if is_get && ok {
        let cache_copy = response.cloned()?;
        ctx.wait_until(async move {
            let _ = cache.put(&req, cache_copy).await;
        });
    }

    Ok(response)
}
