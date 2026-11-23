//! The hub's side of the name service (`name-service.md` in the `keep-name-service`
//! repository): Register, Set address, Set proof, Clear proof. Only the hub talks to it.

use serde_json::json;

use zeroize::Zeroizing;

use crate::client::{Http, Response};

/// The production name service (`names.service`).
pub const NAME_SERVICE: &str = "https://names.getmoneykeep.org/v1";

/// A refusal or failure, with the service's code (`unreachable` when it didn't answer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.status == 0 {
            write!(f, "The name service can't be reached: {}", self.message)
        } else {
            write!(
                f,
                "The name service refused ({}): {}",
                self.code, self.message
            )
        }
    }
}

/// What Register gives, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub id: String,
    pub name: String,
    /// The hub's token: kept sealed, never logged.
    pub token: String,
}

/// What Make tunnel gives: the away name, and the tunnel token for the connector.
pub struct Tunnel {
    pub hostname: String,
    /// Passed on once, in the admin answer; never kept, never logged.
    pub token: Zeroizing<String>,
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("hostname", &self.hostname)
            .finish_non_exhaustive()
    }
}

pub struct NameService<'a> {
    http: &'a dyn Http,
    base: String,
}

impl<'a> NameService<'a> {
    pub fn new(http: &'a dyn Http, base: &str) -> NameService<'a> {
        NameService {
            http,
            base: base.trim_end_matches('/').to_string(),
        }
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        ok: u16,
    ) -> Result<Response, ServiceError> {
        self.call_any(method, path, token, body, &[ok])
    }

    fn call_any(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        ok: &[u16],
    ) -> Result<Response, ServiceError> {
        let auth = token.map(|t| format!("Bearer {t}"));
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(a) = &auth {
            headers.push(("Authorization", a));
        }
        let bytes = body.map(|b| b.to_string().into_bytes());
        if bytes.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        let r = self
            .http
            .send(
                method,
                &format!("{}{path}", self.base),
                &headers,
                bytes.as_deref(),
            )
            .map_err(|e| ServiceError {
                status: 0,
                code: "unreachable".into(),
                message: e,
                retry_after: None,
            })?;
        if ok.contains(&r.status) {
            return Ok(r);
        }
        let v = r.json().unwrap_or(serde_json::Value::Null);
        Err(ServiceError {
            status: r.status,
            code: v["error"].as_str().unwrap_or("unknown").to_string(),
            message: v["message"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("status {}", r.status)),
            retry_after: r.retry_after(),
        })
    }

    /// Register with a registration code (typed as the person typed it).
    pub fn register(&self, code: &str, hub_version: &str) -> Result<Registered, ServiceError> {
        let r = self.call(
            "POST",
            "/hubs",
            None,
            Some(json!({ "registration_code": code, "hub_version": hub_version })),
            201,
        )?;
        let v = r.json().unwrap_or(serde_json::Value::Null);
        let s = |k: &str| v[k].as_str().map(str::to_string);
        match (s("id"), s("name"), s("token")) {
            (Some(id), Some(name), Some(token)) => Ok(Registered { id, name, token }),
            _ => Err(ServiceError {
                status: r.status,
                code: "unreadable".into(),
                message: "the answer can't be read".into(),
                retry_after: None,
            }),
        }
    }

    pub fn set_address(&self, id: &str, token: &str, address: &str) -> Result<(), ServiceError> {
        self.call(
            "PUT",
            &format!("/hubs/{id}/address"),
            Some(token),
            Some(json!({ "address": address })),
            200,
        )
        .map(|_| ())
    }

    pub fn set_proof(&self, id: &str, token: &str, value: &str) -> Result<(), ServiceError> {
        self.call(
            "PUT",
            &format!("/hubs/{id}/proof"),
            Some(token),
            Some(json!({ "value": value })),
            200,
        )
        .map(|_| ())
    }

    /// Make tunnel (revision 1): the tunnel to `port`, its away name, and the tunnel token
    /// (never kept by the hub). Answers `201` the first time and `200` after.
    pub fn make_tunnel(&self, id: &str, token: &str, port: u16) -> Result<Tunnel, ServiceError> {
        let r = self.call_any(
            "POST",
            &format!("/hubs/{id}/tunnel"),
            Some(token),
            Some(json!({ "port": port })),
            &[200, 201],
        )?;
        let v = r.json().unwrap_or(serde_json::Value::Null);
        match (v["hostname"].as_str(), v["token"].as_str()) {
            (Some(h), Some(t)) if !t.is_empty() => Ok(Tunnel {
                hostname: h.to_string(),
                token: Zeroizing::new(t.to_string()),
            }),
            _ => Err(ServiceError {
                status: r.status,
                code: "unreadable".into(),
                message: "the answer can't be read".into(),
                retry_after: None,
            }),
        }
    }

    /// Remove tunnel (revision 1): `204`, also when it is already gone.
    pub fn remove_tunnel(&self, id: &str, token: &str) -> Result<(), ServiceError> {
        self.call(
            "DELETE",
            &format!("/hubs/{id}/tunnel"),
            Some(token),
            None,
            204,
        )
        .map(|_| ())
    }

    pub fn clear_proof(&self, id: &str, token: &str) -> Result<(), ServiceError> {
        self.call(
            "DELETE",
            &format!("/hubs/{id}/proof"),
            Some(token),
            None,
            204,
        )
        .map(|_| ())
    }
}
