use crate::api::response::{
    IotaResponse, OmikronResponse, PublicKeyResponse, StatusResponse, UserResponse,
    UsernameResponse, json,
};
use crate::db::{
    iota_repo::{get_iota_by_id, get_node_descriptor, publish_node_descriptor},
    omikron_repo::get_omikron_by_id,
    user_repo::{
        DescriptorPublicationState, descriptor_publication_state, get_by_user_id, get_by_username,
    },
};
use crate::error::{OmegaError, Result};
use crate::identity::OmegaIdentity;
use crate::models::{IotaId, UserId};
use crate::server::{
    middleware,
    validation::{parse_positive_id, validate_non_empty},
    with_cors,
};
use crate::state::OmegaState;
use crate::transport::omikron_manager::{get_iota_primary_omikron_connection, get_random_omikron};
use crate::util::file_util::get_directory;
use base64::Engine as _;
use bytes::Bytes;
use http::{Method, StatusCode};
use mtp::webserver::{HttpRequest, HttpResponse, RouteParams};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

fn route_name(parts: &[&str]) -> &'static str {
    match parts {
        ["api", "download", "iota_frontend"] => "/api/download/iota_frontend",
        ["api", "get", "user", _] => "/api/get/user/:id",
        ["direct", ..] => "/direct/:short",
        ["api", "get", "id", _] => "/api/get/id/:username",
        ["api", "get", "iota", _] => "/api/get/iota/:id",
        ["api", "get", "iota", _, "omikron"] => "/api/get/iota/:id/omikron",
        ["api", "get", "omikron", _] => "/api/get/omikron/:id",
        ["api", "get", "registration-omikron", _] => "/api/get/registration-omikron/:id",
        ["federation", "v1", "users", "id", _] => "/federation/v1/users/id/:id",
        ["federation", "v1", "users", "name", _] => "/federation/v1/users/name/:username",
        ["federation", "v1", "iotas", _, "node"] => "/federation/v1/iotas/:id/node",
        [".well-known", "tensamin"] => "/.well-known/tensamin",
        ["api", "get", "omikron"] => "/api/get/omikron",
        ["api", "get", "public_key"] => "/api/get/public_key",
        _ => "unmatched",
    }
}

fn error_body(error: &OmegaError, request_id: Uuid, method: &Method) -> String {
    json(&serde_json::json!({
        "status": match error {
            OmegaError::Validation(_) => "error_bad_request",
            OmegaError::NotFound => "error_not_found",
            _ => "error",
        },
        "code": error.code(),
        "message": "The service could not complete the request",
        "request_id": request_id.to_string(),
        // Only safe reads may be replayed after an uncertain dependency failure.
        "retryable": (*method == Method::GET || *method == Method::HEAD)
            && error.status_code() == StatusCode::SERVICE_UNAVAILABLE,
    }))
}

fn user_response(user: crate::models::User) -> Result<UserResponse> {
    Ok(UserResponse {
        status: "success",
        username: user.username,
        public_key: user.public_key.try_to_base64()?,
        user_id: user.id.0,
        iota_id: user.iota_id.map(|id| id.0),
        display: user.display,
        status_message: user.status,
        about: user.about,
        avatar: user
            .avatar
            .map(|value| base64::engine::general_purpose::STANDARD.encode(value)),
    })
}

fn account_principal(identity: &OmegaIdentity, user_id: i64) -> Result<String> {
    if user_id <= 0 {
        return Err(OmegaError::Validation("invalid user ID".into()));
    }
    let authority = iota_identity::AuthorityId::for_omega(&identity.public_key_bundle())
        .map_err(|error| OmegaError::Validation(error.to_string()))?;
    Ok(format!("{}#{user_id}", authority.as_str()))
}

async fn build_omikron_response(state: &OmegaState, omikron_id: i64) -> Result<OmikronResponse> {
    state
        .connected_omikron(omikron_id)
        .ok_or(OmegaError::NotFound)?;
    let omikron = get_omikron_by_id(omikron_id.into()).await?;
    state
        .connected_omikron(omikron_id)
        .ok_or(OmegaError::NotFound)?;
    Ok(OmikronResponse {
        status: "success",
        id: omikron.id.0,
        public_key: omikron.public_key.try_to_base64()?,
        ip_address: omikron.ip_address,
        port: omikron.port,
    })
}

async fn connected_omikron_for_iota(state: &OmegaState, iota_id: i64) -> Result<OmikronResponse> {
    get_iota_by_id(IotaId::from(iota_id)).await?;
    let omikron_id = primary_route_for_iota(state, iota_id)?;
    build_omikron_response(state, omikron_id).await
}

fn primary_route_for_iota(state: &OmegaState, iota_id: i64) -> Result<i64> {
    get_iota_primary_omikron_connection(state, iota_id).ok_or(OmegaError::NotFound)
}

async fn registration_omikron_for_iota(
    state: &OmegaState,
    iota_id: i64,
) -> Result<OmikronResponse> {
    get_iota_by_id(IotaId::from(iota_id)).await?;
    let omikron_id = match get_iota_primary_omikron_connection(state, iota_id) {
        Some(id) => id,
        None => get_random_omikron(state)
            .await
            .map_err(|_| OmegaError::NotConnected)?
            .get_omikron_id()
            .await
            .ok_or(OmegaError::NotFound)?,
    };
    build_omikron_response(state, omikron_id).await
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub(crate) async fn federation_user_descriptor(
    user: crate::models::User,
    identity: &OmegaIdentity,
) -> Result<iota_identity::PrincipalDescriptorWireV1> {
    let iota_id = user.iota_id.ok_or(OmegaError::NotFound)?;
    let home_node = get_node_descriptor(iota_id).await?;
    let verified_node = home_node
        .clone()
        .parse()
        .and_then(|descriptor| descriptor.verify(None, now_millis()))
        .map_err(|error| OmegaError::Validation(error.to_string()))?;
    let source = serde_json::to_vec(&(
        &user.username,
        &user.display,
        user.public_key.try_to_base64()?,
        verified_node.descriptor().node.as_str(),
        verified_node.descriptor().valid_until,
    ))
    .map_err(|error| OmegaError::Validation(error.to_string()))?;
    let publication = descriptor_publication_state(
        user.id,
        &source,
        verified_node.descriptor().valid_until,
        now_millis(),
    )
    .await?;
    sign_federation_user_descriptor(user, home_node, publication, identity)
}

fn sign_federation_user_descriptor(
    user: crate::models::User,
    home_node: iota_identity::NodeDescriptorWireV1,
    publication: DescriptorPublicationState,
    identity: &OmegaIdentity,
) -> Result<iota_identity::PrincipalDescriptorWireV1> {
    let verified_node = home_node
        .clone()
        .parse()
        .and_then(|descriptor| descriptor.verify(None, now_millis()))
        .map_err(|error| OmegaError::Validation(error.to_string()))?;
    let authority = iota_identity::AuthorityId::for_omega(&identity.public_key_bundle())
        .map_err(|error| OmegaError::Validation(error.to_string()))?;
    let user_id = u64::try_from(user.id.0)
        .map_err(|_| OmegaError::Validation("user ID is outside federation range".into()))?;
    iota_identity::SignedPrincipalDescriptor::sign(
        iota_identity::PrincipalDescriptor {
            principal: iota_identity::PrincipalId { authority, user_id },
            authority_kind: iota_identity::AuthorityKind::Omega,
            username: Some(user.username),
            display_name: user.display,
            public_keys: vec![user.public_key],
            home: iota_identity::PrincipalHome::Iota(verified_node.descriptor().node.clone()),
            revision: publication.revision,
            valid_until: publication.valid_until,
            issued_at: publication.issued_at,
        },
        identity.keyring(),
    )
    .and_then(|descriptor| descriptor.to_wire_v1())
    .map(|descriptor| descriptor.with_home_node(home_node))
    .map_err(|error| OmegaError::Validation(error.to_string()))
}

async fn route(
    path_parts: &[&str],
    method: &Method,
    body: Option<&Bytes>,
    identity: &OmegaIdentity,
    state: &OmegaState,
) -> Result<(StatusCode, String)> {
    match path_parts {
        [".well-known", "tensamin"] if method == Method::GET => {
            let public_key = identity.public_key_bundle();
            let authority_id = iota_identity::AuthorityId::for_omega(&public_key)
                .map_err(|error| OmegaError::Validation(error.to_string()))?;
            Ok((
                StatusCode::OK,
                json(&iota_identity::AuthorityDiscoveryDocument {
                    version: 1,
                    service: iota_identity::AuthorityKind::Omega,
                    authority_id,
                    node_id: None,
                    public_key: public_key.try_to_base64()?,
                    protocols: vec!["identity-http-v1".into()],
                    node_descriptor: None,
                    direct_endpoints: Vec::new(),
                    relay_hints: Vec::new(),
                }),
            ))
        }
        ["federation", "v1", "users", "id", id] if method == Method::GET => {
            let user = get_by_user_id(UserId::from(parse_positive_id(id)?)).await?;
            Ok((
                StatusCode::OK,
                json(&federation_user_descriptor(user, identity).await?),
            ))
        }
        ["federation", "v1", "users", "name", username] if method == Method::GET => {
            validate_non_empty(username, "username", 15)?;
            let user = get_by_username(username).await?;
            Ok((
                StatusCode::OK,
                json(&federation_user_descriptor(user, identity).await?),
            ))
        }
        ["federation", "v1", "iotas", id, "node"] if method == Method::POST => {
            let body = body.ok_or_else(|| {
                OmegaError::Validation("node descriptor request body is missing".into())
            })?;
            let descriptor = serde_json::from_slice(body)
                .map_err(|error| OmegaError::Validation(error.to_string()))?;
            let descriptor =
                publish_node_descriptor(IotaId::from(parse_positive_id(id)?), descriptor).await?;
            Ok((StatusCode::OK, json(&descriptor)))
        }
        ["api", "get", "omikron"] => {
            let connection = get_random_omikron(state)
                .await
                .map_err(|_| OmegaError::NotConnected)?;
            let id = connection
                .get_omikron_id()
                .await
                .ok_or(OmegaError::NotFound)?;
            let omikron = get_omikron_by_id(id.into()).await?;
            Ok((
                StatusCode::OK,
                json(&OmikronResponse {
                    status: "success",
                    id,
                    public_key: omikron.public_key.try_to_base64()?,
                    ip_address: omikron.ip_address,
                    port: omikron.port,
                }),
            ))
        }
        ["api", "get", "omikron", id] => {
            let id = parse_positive_id(id)?;
            let omikron_id = if state.connected_omikron(id).is_some() {
                id
            } else if let Some(omikron_id) = get_iota_primary_omikron_connection(state, id) {
                omikron_id
            } else {
                let user = get_by_user_id(UserId::from(id)).await?;
                match user.iota_id {
                    Some(iota_id) => get_iota_primary_omikron_connection(state, iota_id.0),
                    None => {
                        get_random_omikron(state)
                            .await
                            .map_err(|_| OmegaError::NotConnected)?
                            .get_omikron_id()
                            .await
                    }
                }
                .ok_or(OmegaError::NotFound)?
            };

            // Database rows describe registered Omikrons. The public discovery
            // API must expose only routes backed by a currently live transport.
            state
                .connected_omikron(omikron_id)
                .ok_or(OmegaError::NotFound)?;
            let omikron = get_omikron_by_id(omikron_id.into()).await?;
            Ok((
                StatusCode::OK,
                json(&OmikronResponse {
                    status: "success",
                    id: omikron.id.0,
                    public_key: omikron.public_key.try_to_base64()?,
                    ip_address: omikron.ip_address,
                    port: omikron.port,
                }),
            ))
        }
        ["api", "get", "iota", id, "omikron"] if method == Method::GET => {
            let iota_id = parse_positive_id(id)?;
            Ok((
                StatusCode::OK,
                json(&connected_omikron_for_iota(state, iota_id).await?),
            ))
        }
        ["api", "get", "registration-omikron", id] if method == Method::GET => {
            let iota_id = parse_positive_id(id)?;
            Ok((
                StatusCode::OK,
                json(&registration_omikron_for_iota(state, iota_id).await?),
            ))
        }
        ["api", "get", "iota", id] => {
            let id = parse_positive_id(id)?;
            let iota = get_iota_by_id(id.into()).await?;
            Ok((
                StatusCode::OK,
                json(&IotaResponse {
                    status: "success",
                    iota_id: iota.id.0,
                    public_key: iota.public_key.try_to_base64()?,
                }),
            ))
        }
        ["api", "get", "id", username] => {
            validate_non_empty(username, "username", 15)?;
            let user = get_by_username(username).await?;
            Ok((
                StatusCode::OK,
                json(&UsernameResponse {
                    status: "success",
                    username: user.username,
                    public_key: user.public_key.try_to_base64()?,
                    principal: account_principal(identity, user.id.0)?,
                    user_id: user.id.0,
                    iota_id: user.iota_id.map(|id| id.0),
                }),
            ))
        }
        ["api", "get", "public_key"] => {
            let public_key = base64::engine::general_purpose::STANDARD
                .encode(identity.public_key_bundle().try_as_bytes()?);
            Ok((
                StatusCode::OK,
                json(&PublicKeyResponse {
                    status: "success",
                    public_key,
                }),
            ))
        }
        ["api", "get", "user", id] => {
            let id = parse_positive_id(id)?;
            let user = get_by_user_id(UserId::from(id)).await?;
            Ok((StatusCode::OK, json(&user_response(user)?)))
        }
        _ => Err(OmegaError::NotFound),
    }
}

pub async fn handle(
    request: HttpRequest,
    response: HttpResponse,
    state: Arc<OmegaState>,
) -> HttpResponse {
    let started = Instant::now();
    let request_id = Uuid::new_v4();
    let method = request.method;
    let path = request.uri.path().to_string();
    let path_parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let route_label = route_name(&path_parts);
    let finish = |response: HttpResponse, status: StatusCode| {
        crate::log_event!(
            0,
            crate::util::logger::PrintType::Omega,
            crate::util::logger::LogLevel::Info,
            "http.request_completed",
            "request_id={} method={} route={} status={} elapsed_ms={}",
            request_id,
            method,
            route_label,
            status.as_u16(),
            started.elapsed().as_millis()
        );
        with_cors(
            response
                .header("x-request-id", &request_id.to_string())
                .header("cache-control", "no-store"),
        )
    };
    if method != Method::OPTIONS && !middleware::allow(request.remote_addr.ip(), &path) {
        return finish(
            response
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(json(&StatusResponse {
                    status: "error_rate_limited",
                })),
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    if method == Method::OPTIONS {
        return finish(
            response.status(StatusCode::NO_CONTENT),
            StatusCode::NO_CONTENT,
        );
    }
    if let ["api", "download", "iota_frontend"] = path_parts.as_slice() {
        let file_path = format!("{}/downloads/iota_frontend.zip", get_directory());
        return match tokio::fs::File::open(file_path).await {
            Ok(mut file) => {
                let content_length = file.metadata().await.ok().map(|metadata| metadata.len());
                let (tx, rx) = tokio::sync::mpsc::channel(8);
                tokio::spawn(async move {
                    let mut buffer = vec![0_u8; 64 * 1024];
                    loop {
                        let read = match file.read(&mut buffer).await {
                            Ok(0) => return,
                            Err(error) => {
                                crate::log_event!(
                                    0,
                                    crate::util::logger::PrintType::Omega,
                                    crate::util::logger::LogLevel::Error,
                                    "http.download_read_failed",
                                    "request_id={} error={}",
                                    request_id,
                                    error
                                );
                                return;
                            }
                            Ok(read) => read,
                        };
                        if tx
                            .send(Bytes::copy_from_slice(&buffer[..read]))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
                let mut response = response
                    .status(StatusCode::OK)
                    .header("content-type", "application/zip")
                    .header(
                        "content-disposition",
                        "attachment; filename=\"iota_frontend.zip\"",
                    )
                    .stream(rx);
                if let Some(content_length) = content_length {
                    response = response.header("content-length", &content_length.to_string());
                }
                finish(response, StatusCode::OK)
            }
            Err(_) => finish(
                response
                    .status(StatusCode::NOT_FOUND)
                    .body(json(&StatusResponse {
                        status: "error_not_found",
                    })),
                StatusCode::NOT_FOUND,
            ),
        };
    }
    if let ["direct", short @ ..] = path_parts.as_slice() {
        let short = short.join("");
        return match crate::server::short_link::get_short_link(&short).await {
            Ok(location) => finish(
                response
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", &location)
                    .header("cache-control", "no-store")
                    .header("referrer-policy", "no-referrer"),
                StatusCode::TEMPORARY_REDIRECT,
            ),
            Err(_) => finish(
                response
                    .status(StatusCode::NOT_FOUND)
                    .header("cache-control", "no-store")
                    .header("referrer-policy", "no-referrer")
                    .body(json(&StatusResponse {
                        status: "error_not_found",
                    })),
                StatusCode::NOT_FOUND,
            ),
        };
    }
    let (status, body) = route(
        &path_parts,
        &method,
        request.body.as_ref(),
        &state.identity,
        &state,
    )
    .await
    .unwrap_or_else(|error| {
        crate::log_event!(
            0,
            crate::util::logger::PrintType::Omega,
            if error.status_code().is_server_error() {
                crate::util::logger::LogLevel::Error
            } else {
                crate::util::logger::LogLevel::Warn
            },
            "http.request_failed",
            "request_id={} method={} route={} error_class={} elapsed_ms={} error={}",
            request_id,
            method,
            route_label,
            error.code(),
            started.elapsed().as_millis(),
            error
        );
        (error.status_code(), error_body(&error, request_id, &method))
    });
    finish(response.status(status).body(body), status)
}

pub async fn handle_pattern(
    request: HttpRequest,
    response: HttpResponse,
    _params: RouteParams,
    state: Arc<OmegaState>,
) -> HttpResponse {
    handle(request, response, state).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iota_identity::{LocalNodeIdentity, NodeDescriptor, SignedNodeDescriptor};
    use mtp::crypto::Keyring;

    #[test]
    fn password_iota_route_requires_primary_route() {
        let state = OmegaState::test_state();
        assert!(matches!(
            primary_route_for_iota(&state, 11),
            Err(OmegaError::NotFound)
        ));
        state.presence.connect_iota(11, 42);
        assert_eq!(primary_route_for_iota(&state, 11).unwrap(), 42);
        assert!(matches!(
            primary_route_for_iota(&state, 12),
            Err(OmegaError::NotFound)
        ));
    }

    #[test]
    fn omega_descriptor_binds_user_to_verified_hosting_iota() {
        let omega = OmegaIdentity::from_keyring(Keyring::generate());
        let iota = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
        let user_keyring = Keyring::generate();
        let now = now_millis();
        let node = SignedNodeDescriptor::sign(
            NodeDescriptor {
                node: iota.node_id().clone(),
                public_keys: iota.public_keys(),
                direct_endpoints: vec![
                    iota_identity::AuthorityLocator::new("iota.example:1984").unwrap(),
                ],
                relay_hints: Vec::new(),
                revision: 4,
                valid_until: Some(now + 60_000),
            },
            &iota,
        )
        .unwrap()
        .to_wire_v1()
        .unwrap();
        let wire = sign_federation_user_descriptor(
            crate::models::User {
                id: UserId::from(7),
                iota_id: Some(IotaId::from(11)),
                username: "alice".into(),
                display: Some("Alice".into()),
                status: None,
                presence_preference: "user_online".into(),
                about: None,
                avatar: None,
                sub_level: 0,
                sub_end: 0,
                public_key: user_keyring.public_key_bundle(),
                token: String::new(),
                created_at: now,
            },
            node,
            DescriptorPublicationState {
                revision: 3,
                issued_at: now,
                valid_until: Some(now + 60_000),
            },
            &omega,
        )
        .unwrap();
        let authority = iota_identity::AuthorityId::for_omega(&omega.public_key_bundle()).unwrap();
        let verified = wire
            .clone()
            .parse()
            .unwrap()
            .verify(&authority, &omega.public_key_bundle(), None, now)
            .unwrap();
        assert_eq!(verified.descriptor().principal.user_id, 7);
        assert_eq!(
            verified.descriptor().home,
            iota_identity::PrincipalHome::Iota(iota.node_id().clone())
        );
        assert_eq!(wire.home_node.unwrap().revision, 4);
    }

    #[test]
    fn public_account_principal_uses_omega_key_identity() {
        let omega = OmegaIdentity::from_keyring(Keyring::generate());
        let authority = iota_identity::AuthorityId::for_omega(&omega.public_key_bundle()).unwrap();
        assert_eq!(
            account_principal(&omega, 7).unwrap(),
            format!("{}#7", authority.as_str())
        );
        assert!(account_principal(&omega, 0).is_err());
    }

    #[test]
    fn iota_omikron_discovery_has_an_explicit_route() {
        assert_eq!(
            route_name(&["api", "get", "iota", "7", "omikron"]),
            "/api/get/iota/:id/omikron"
        );
        assert_eq!(
            route_name(&["api", "get", "registration-omikron", "7"]),
            "/api/get/registration-omikron/:id"
        );
    }
}
