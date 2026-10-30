//! The iPhone app in the user portal (ADR-0019).
//!
//! - **Register this iPhone:** a signed-in user downloads a registration
//!   profile (`register.mobileconfig`, Apple's "Profile Service"). iOS
//!   posts the iPhone's UDID back to the link inside it, which carries a
//!   one-time token tied to the user; an administrator approves the request
//!   in the console.
//! - **Install:** iOS installs Ad Hoc apps only from an
//!   `itms-services://` link to a manifest, fetching the manifest and the app
//!   itself without the user's session; both links carry a short-lived token.
//!   iOS requires a publicly trusted HTTPS certificate on the portal
//!   (Cloudflare, Let's Encrypt).

use super::appliance::FileBody;
use super::{blocking, Ctx};
use crate::auth::Permission;
use crate::http_util::{ApiError, ApiResult};
use crate::ManagementContext;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use serde_json::{json, Value};

/// A registration link is used once, within this time.
const REGISTER_TTL: i64 = 30 * 60;
/// Install links (manifest and app) work for this long.
const INSTALL_TTL: i64 = 60 * 60;
const MAX_LINKS: usize = 1000;
/// What iOS posts back: a small signed plist.
const MAX_CALLBACK: usize = 64 * 1024;

/// A link handed to iOS (which can't present the user's session).
#[derive(Clone)]
pub(crate) struct IosLink {
    principal: String,
    username: String,
    expires: i64,
    register: bool,
}

fn now() -> i64 {
    aegis_storage::now_unix()
}

fn new_link(ctx: &ManagementContext, link: IosLink) -> String {
    let token = crate::auth::random_token();
    let mut links = ctx.ios_links.lock().unwrap_or_else(|e| e.into_inner());
    let t = now();
    links.retain(|_, l| l.expires > t);
    if links.len() >= MAX_LINKS {
        // Oldest first.
        if let Some(k) = links
            .iter()
            .min_by_key(|(_, l)| l.expires)
            .map(|(k, _)| k.clone())
        {
            links.remove(&k);
        }
    }
    links.insert(token.clone(), link);
    token
}

/// The link for `token` when valid (a registration link is used up).
fn take_link(ctx: &ManagementContext, token: &str, register: bool) -> Option<IosLink> {
    let mut links = ctx.ios_links.lock().unwrap_or_else(|e| e.into_inner());
    let link = links
        .get(token)
        .filter(|l| l.expires > now() && l.register == register)?
        .clone();
    if register {
        links.remove(token);
    }
    Some(link)
}

/// The portal's public address (`https://host/portal/`): what iOS reaches.
fn portal(ctx: &ManagementContext) -> Result<String, ApiError> {
    crate::portal::url(ctx).ok_or_else(|| {
        ApiError::conflict("portal_address_unknown")
            .detail("set the gateway's public address first (Connectivity)")
    })
}

async fn ios_action(ctx: &Ctx, action: &str, actor: &str, body: Value) -> Result<Value, ApiError> {
    let appliance = ctx
        .appliance()
        .ok_or_else(|| ApiError::conflict("appliance_mode_required"))?;
    appliance
        .integration("ios", action, actor, body)
        .await
        .map_err(|(status, detail)| {
            ApiError::new(
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                "ios_failed",
            )
            .detail(detail)
        })
}

async fn username(ctx: &Ctx, principal: &str) -> String {
    let (c, id) = (ctx.clone(), principal.to_owned());
    blocking(move || {
        c.coord
            .store()
            .read(|s| aegis_storage::get_principal(s, &id))
            .map(|p| p.username)
            .map_err(ApiError::from)
    })
    .await
    .unwrap_or_default()
}

/// `GET /api/v1/ios`: the user's iPhone requests and, when the app is
/// here, an install link.
pub async fn status(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::DevicesSelf)?;
    let mut out = ios_action(&ctx, "mine", &p.id, json!({})).await?;
    let base = crate::portal::url(&ctx);
    if out["app"].is_object() {
        if let Some(base) = &base {
            let token = new_link(
                &ctx,
                IosLink {
                    principal: p.id.clone(),
                    username: String::new(),
                    expires: now() + INSTALL_TTL,
                    register: false,
                },
            );
            let manifest = format!("{base}api/v1/ios/manifest/{token}");
            out["install"] = json!(format!(
                "itms-services://?action=download-manifest&url={}",
                percent_encode(&manifest)
            ));
        }
    }
    out["portal"] = json!(base);
    Ok(crate::http_util::json(StatusCode::OK, &out, &[]))
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// `GET /api/v1/ios/register.mobileconfig`: the registration profile.
pub async fn register_profile(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::DevicesSelf)?;
    let base = portal(&ctx)?;
    let name = username(&ctx, &p.id).await;
    let token = new_link(
        &ctx,
        IosLink {
            principal: p.id.clone(),
            username: name,
            expires: now() + REGISTER_TTL,
            register: true,
        },
    );
    let callback = format!("{base}api/v1/ios/udid/{token}");
    let uuid = crate::auth::random_token();
    let profile = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<dict>
		<key>URL</key>
		<string>{callback}</string>
		<key>DeviceAttributes</key>
		<array>
			<string>UDID</string>
			<string>PRODUCT</string>
			<string>VERSION</string>
			<string>DEVICE_NAME</string>
		</array>
	</dict>
	<key>PayloadOrganization</key>
	<string>AegisBorne</string>
	<key>PayloadDisplayName</key>
	<string>AegisBorne iPhone registration</string>
	<key>PayloadDescription</key>
	<string>Sends this iPhone's identifier (UDID) to your AegisBorne server so the app can be installed on it. Nothing stays installed.</string>
	<key>PayloadIdentifier</key>
	<string>borne.aegis.register</string>
	<key>PayloadUUID</key>
	<string>{uuid}</string>
	<key>PayloadType</key>
	<string>Profile Service</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#,
        callback = xml(&callback),
        uuid = xml(&uuid),
    );
    let mut resp = axum::response::Response::new(Body::from(profile));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/x-apple-aspen-config"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        http::HeaderValue::from_static("attachment; filename=\"aegisborne-register.mobileconfig\""),
    );
    h.insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

/// The device attributes in what iOS posts back: a plist inside a CMS
/// signature (the signature itself isn't needed: the token says who asked).
pub(crate) fn device_attributes(body: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(body);
    let start = text.find("<plist")?;
    let end = text[start..].find("</plist>")? + start;
    let plist = &text[start..end];
    let value = |key: &str| -> Option<String> {
        let at = plist.find(&format!("<key>{key}</key>"))?;
        let rest = &plist[at..];
        let open = rest.find("<string>")? + "<string>".len();
        let close = rest[open..].find("</string>")? + open;
        Some(rest[open..close].trim().to_owned())
    };
    Some(json!({
        "udid": value("UDID")?,
        "product": value("PRODUCT").unwrap_or_default(),
        "ios": value("VERSION").unwrap_or_default(),
        "name": value("DEVICE_NAME").unwrap_or_default(),
    }))
}

/// `POST /api/v1/ios/udid/{token}`: iOS sends the registration back.
pub async fn udid(
    State(ctx): State<Ctx>,
    Path(token): Path<String>,
    body: Body,
) -> impl IntoResponse {
    let base = crate::portal::url(&ctx).unwrap_or_else(|| "/portal/".into());
    let redirect = |state: &str| {
        (
            StatusCode::MOVED_PERMANENTLY,
            [(header::LOCATION, format!("{base}#ios-{state}"))],
        )
            .into_response()
    };
    let Some(link) = take_link(&ctx, &token, true) else {
        return redirect("expired");
    };
    let Ok(bytes) = axum::body::to_bytes(body, MAX_CALLBACK).await else {
        return redirect("failed");
    };
    let Some(mut attributes) = device_attributes(&bytes) else {
        return redirect("failed");
    };
    attributes["username"] = json!(link.username);
    match ios_action(&ctx, "request", &link.principal, attributes).await {
        Ok(_) => redirect("registered"),
        Err(_) => redirect("failed"),
    }
}

/// `GET /api/v1/ios/manifest/{token}`: what `itms-services` reads.
pub async fn manifest(State(ctx): State<Ctx>, Path(token): Path<String>) -> ApiResult {
    let link = take_link(&ctx, &token, false).ok_or_else(ApiError::not_found)?;
    let info = ios_action(&ctx, "mine", &link.principal, json!({})).await?;
    let version = info["app"]["version"]
        .as_str()
        .ok_or_else(ApiError::not_found)?
        .to_owned();
    let base = portal(&ctx)?;
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>items</key>
	<array>
		<dict>
			<key>assets</key>
			<array>
				<dict>
					<key>kind</key>
					<string>software-package</string>
					<key>url</key>
					<string>{url}</string>
				</dict>
			</array>
			<key>metadata</key>
			<dict>
				<key>bundle-identifier</key>
				<string>borne.aegis.app</string>
				<key>bundle-version</key>
				<string>{version}</string>
				<key>kind</key>
				<string>software</string>
				<key>title</key>
				<string>AegisBorne</string>
			</dict>
		</dict>
	</array>
</dict>
</plist>
"#,
        url = xml(&format!("{base}api/v1/ios/app/{token}")),
        version = xml(&version),
    );
    let mut resp = axum::response::Response::new(Body::from(plist));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/xml"),
    );
    h.insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

/// `GET /api/v1/ios/app/{token}`: the app itself, streamed from disk.
pub async fn app(State(ctx): State<Ctx>, Path(token): Path<String>) -> ApiResult {
    take_link(&ctx, &token, false).ok_or_else(ApiError::not_found)?;
    let dir = ctx.data_dir().ok_or_else(ApiError::not_found)?;
    let file = tokio::fs::File::open(dir.join("ios/app.ipa"))
        .await
        .map_err(|_| ApiError::not_found())?;
    let len = file
        .metadata()
        .await
        .map_err(|_| ApiError::not_found())?
        .len();
    let mut resp = axum::response::Response::new(Body::new(FileBody::new(file, len)));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_udid_is_read_from_what_ios_posts() {
        // As iOS sends it: the plist inside a signature (binary around it).
        let mut body = b"\x30\x80\x06\x09garbage".to_vec();
        body.extend_from_slice(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>PRODUCT</key><string>iPhone7,2</string>
<key>UDID</key><string>447c2b96bb63020799bbd2c659a98af8edf3b525</string>
<key>VERSION</key><string>16G183</string>
</dict></plist>"#,
        );
        body.extend_from_slice(b"\xa0\x82signature");
        let a = device_attributes(&body).expect("attributes");
        assert_eq!(a["udid"], "447c2b96bb63020799bbd2c659a98af8edf3b525");
        assert_eq!(a["product"], "iPhone7,2");
        assert_eq!(a["name"], "");
        assert!(device_attributes(b"no plist here").is_none());
    }

    #[test]
    fn install_links_are_encoded_for_itms_services() {
        assert_eq!(
            percent_encode("https://h/portal/api/v1/ios/manifest/a_b-c"),
            "https%3A%2F%2Fh%2Fportal%2Fapi%2Fv1%2Fios%2Fmanifest%2Fa_b-c"
        );
    }
}
