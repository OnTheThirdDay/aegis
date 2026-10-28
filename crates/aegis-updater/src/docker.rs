//! A minimal Docker Engine API client: HTTP/1.1 over the Unix socket, one
//! request per connection, JSON bodies. Only what the updater needs.

use serde_json::Value;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub struct DockerError(pub String);

impl std::fmt::Display for DockerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DockerError {}

fn err(e: impl std::fmt::Display) -> DockerError {
    DockerError(e.to_string())
}

pub struct Docker {
    socket: PathBuf,
}

/// Responses larger than this are refused (image lists, inspect output and
/// pull progress are far smaller).
const MAX_RESPONSE: usize = 32 * 1024 * 1024;

impl Docker {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Docker {
            socket: socket.into(),
        }
    }

    /// One request. `timeout` bounds every read and write (a pull streams
    /// progress, so it only needs to keep moving).
    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> Result<(u16, Value), DockerError> {
        let mut s = UnixStream::connect(&self.socket).map_err(err)?;
        s.set_read_timeout(Some(timeout)).map_err(err)?;
        s.set_write_timeout(Some(timeout)).map_err(err)?;
        let body = body.map(Value::to_string).unwrap_or_default();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        s.write_all(head.as_bytes()).map_err(err)?;
        s.write_all(body.as_bytes()).map_err(err)?;
        let mut raw = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = s.read(&mut buf).map_err(err)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.len() > MAX_RESPONSE {
                return Err(DockerError("response too large".into()));
            }
        }
        parse_response(&raw)
    }

    fn json(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, DockerError> {
        let (status, v) = self.request(method, path, body, Duration::from_secs(30))?;
        if !(200..300).contains(&status) {
            return Err(DockerError(format!(
                "{method} {path}: {status} {}",
                v["message"].as_str().unwrap_or("")
            )));
        }
        Ok(v)
    }

    /// `None` when there is no such container.
    pub fn inspect_container(&self, name: &str) -> Result<Option<Value>, DockerError> {
        let (status, v) = self.request(
            "GET",
            &format!("/containers/{}/json", enc(name)),
            None,
            Duration::from_secs(30),
        )?;
        match status {
            200 => Ok(Some(v)),
            404 => Ok(None),
            s => Err(DockerError(format!("inspect {name}: {s}"))),
        }
    }

    pub fn inspect_image(&self, reference: &str) -> Result<Option<Value>, DockerError> {
        let (status, v) = self.request(
            "GET",
            &format!("/images/{}/json", enc(reference)),
            None,
            Duration::from_secs(30),
        )?;
        match status {
            200 => Ok(Some(v)),
            404 => Ok(None),
            s => Err(DockerError(format!("inspect image {reference}: {s}"))),
        }
    }

    /// Local images of `repository` (`ghcr.io/owner/name`).
    pub fn images(&self, repository: &str) -> Result<Vec<Value>, DockerError> {
        let filters = serde_json::json!({ "reference": [repository] }).to_string();
        let v = self.json(
            "GET",
            &format!("/images/json?filters={}", enc(&filters)),
            None,
        )?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }

    /// Pull `repository:tag`; the error carries the registry's message.
    pub fn pull(&self, repository: &str, tag: &str, timeout: Duration) -> Result<(), DockerError> {
        let (status, v) = self.request(
            "POST",
            &format!(
                "/images/create?fromImage={}&tag={}",
                enc(repository),
                enc(tag)
            ),
            None,
            timeout,
        )?;
        if status != 200 {
            return Err(DockerError(format!(
                "pull: {status} {}",
                v["message"].as_str().unwrap_or("")
            )));
        }
        // Errors after the 200 arrive in the progress stream.
        if let Some(e) = v["error"].as_str() {
            return Err(DockerError(format!("pull: {e}")));
        }
        Ok(())
    }

    pub fn tag(&self, image: &str, repository: &str, tag: &str) -> Result<(), DockerError> {
        self.json(
            "POST",
            &format!(
                "/images/{}/tag?repo={}&tag={}",
                enc(image),
                enc(repository),
                enc(tag)
            ),
            None,
        )
        .map(|_| ())
    }

    pub fn create(&self, name: &str, config: &Value) -> Result<String, DockerError> {
        let v = self.json(
            "POST",
            &format!("/containers/create?name={}", enc(name)),
            Some(config),
        )?;
        v["Id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| DockerError("create: no id".into()))
    }

    pub fn start(&self, name: &str) -> Result<(), DockerError> {
        let (status, v) = self.request(
            "POST",
            &format!("/containers/{}/start", enc(name)),
            None,
            Duration::from_secs(60),
        )?;
        match status {
            204 | 304 => Ok(()),
            s => Err(DockerError(format!(
                "start {name}: {s} {}",
                v["message"].as_str().unwrap_or("")
            ))),
        }
    }

    pub fn stop(&self, name: &str, grace_secs: u64) -> Result<(), DockerError> {
        let (status, _) = self.request(
            "POST",
            &format!("/containers/{}/stop?t={grace_secs}", enc(name)),
            None,
            Duration::from_secs(grace_secs + 30),
        )?;
        match status {
            204 | 304 | 404 => Ok(()),
            s => Err(DockerError(format!("stop {name}: {s}"))),
        }
    }

    pub fn rename(&self, name: &str, to: &str) -> Result<(), DockerError> {
        self.json(
            "POST",
            &format!("/containers/{}/rename?name={}", enc(name), enc(to)),
            None,
        )
        .map(|_| ())
    }

    pub fn remove(&self, name: &str) -> Result<(), DockerError> {
        let (status, _) = self.request(
            "DELETE",
            &format!("/containers/{}?force=true", enc(name)),
            None,
            Duration::from_secs(60),
        )?;
        match status {
            204 | 404 => Ok(()),
            s => Err(DockerError(format!("remove {name}: {s}"))),
        }
    }
}

/// Percent-encode a path or query component.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Status and JSON body of a complete HTTP/1.1 response. A streamed body of
/// several JSON documents (pull progress) yields the last one.
fn parse_response(raw: &[u8]) -> Result<(u16, Value), DockerError> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| DockerError("malformed response".into()))?;
    let head = std::str::from_utf8(&raw[..end]).map_err(err)?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| DockerError("malformed status line".into()))?;
    let chunked = lines.any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = &raw[end + 4..];
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    let text = String::from_utf8_lossy(&body);
    let value = serde_json::from_str(&text).unwrap_or_else(|_| {
        // A stream of JSON objects: keep the last one that parses, but
        // surface any error the stream reported.
        let mut last = Value::Null;
        for doc in serde_json::Deserializer::from_str(&text)
            .into_iter::<Value>()
            .flatten()
        {
            if doc.get("error").is_some() {
                return doc;
            }
            last = doc;
        }
        last
    });
    Ok((status, value))
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, DockerError> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| DockerError("malformed chunk".into()))?;
        let size_text = std::str::from_utf8(&body[..line_end]).map_err(err)?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| DockerError("malformed chunk size".into()))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size {
            // A stream cut short: what arrived is still useful.
            out.extend_from_slice(body);
            return Ok(out);
        }
        out.extend_from_slice(&body[..size]);
        body = body.get(size + 2..).unwrap_or(&[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses_plain_chunked_and_streamed() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"Id\":\"ab\"}";
        let (s, v) = parse_response(plain).expect("plain");
        assert_eq!((s, v["Id"].as_str()), (200, Some("ab")));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1}\r\n7\r\n{\"b\":2}\r\n0\r\n\r\n";
        let (_, v) = parse_response(chunked).expect("chunked");
        assert_eq!(v["b"], 2, "last document of a stream");
        let failed = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1b\r\n{\"status\":\"Pulling\"}{\"x\":1}\r\n12\r\n{\"error\":\"denied\"}\r\n0\r\n\r\n";
        let (_, v) = parse_response(failed).expect("stream");
        assert_eq!(v["error"], "denied");
        let missing = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_response(missing).expect("404").0, 404);
        assert!(parse_response(b"garbage").is_err());
    }

    #[test]
    fn components_are_encoded() {
        assert_eq!(enc("ghcr.io/owner/aegis"), "ghcr.io%2Fowner%2Faegis");
        assert_eq!(enc("0.7.0"), "0.7.0");
        assert_eq!(enc("{\"a\":[1]}"), "%7B%22a%22%3A%5B1%5D%7D");
    }
}
