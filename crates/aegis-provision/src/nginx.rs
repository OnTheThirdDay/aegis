//! Optional isolated Nginx site. Docker lifecycle/validation is owned by the
//! local installer; no host-wide nginx.conf or independent site is modified.
use crate::{Error, Result};

pub fn config(hostname: &str, certificate: &str, key: &str) -> Result<String> {
    if aegis_contracts::destination::normalize_domain(hostname).as_deref() != Ok(hostname)
        || [certificate, key].iter().any(|s| {
            s.is_empty()
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(Error("invalid_nginx_configuration"));
    }
    Ok(format!(
        r#"pid /tmp/nginx.pid;
error_log /dev/null crit;
events {{ worker_connections 256; }}
http {{
  access_log off;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
  server {{
    listen 8443 ssl;
    server_name {hostname};
    ssl_protocols TLSv1.3;
    ssl_session_tickets off;
    ssl_certificate /etc/aegisnet/{certificate};
    ssl_certificate_key /etc/aegisnet/{key};
    add_header X-Content-Type-Options nosniff always;
    add_header Strict-Transport-Security "max-age=31536000" always;
    location = /agp {{
      proxy_pass http://gateway:18080;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_set_header Host $host;
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_read_timeout 3600s;
      proxy_send_timeout 3600s;
    }}
    location / {{ return 404; }}
  }}
}}
"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dedicated_ws_site_does_not_route_admin_or_accept_injected_directives() {
        let rendered = config("edge.example.test", "cert.pem", "key.pem").expect("config");
        assert!(
            rendered.contains("location = /agp") && rendered.contains("proxy_http_version 1.1")
        );
        assert!(!rendered.contains("9080") && !rendered.contains("/api/"));
        assert!(config(
            "edge.example.test; include /etc/shadow;",
            "cert.pem",
            "key.pem"
        )
        .is_err());
        assert!(config("edge.example.test", "../cert.pem", "key.pem").is_err());
    }
}
