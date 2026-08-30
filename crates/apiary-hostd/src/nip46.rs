//! NIP-46 remote signer support.
//!
//! Apiary owns only a disposable client key. The human signing key remains
//! in the bunker and is used here only for login and kind-4600 governance
//! ratifications.

use crate::{err, nip98, ops, App, AuthMode};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use nostr::{
    nips::{nip44, nip46},
    prelude::*,
};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const RATIFICATION_KIND: u16 = 4600;
const CONNECTION_TTL_SECS: u64 = 10 * 60;

#[derive(Clone)]
pub struct RemoteSigner {
    client_keys: Keys,
    remote_signer: PublicKey,
    relays: Vec<String>,
    user: Option<PublicKey>,
    stage: ConnectStage,
    pending_connect: Option<PendingRequest>,
    pending_sign: Option<PendingRequest>,
    created_at: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectStage {
    Connect,
    PublicKey,
    Ready,
}

#[derive(Clone)]
struct PendingRequest {
    id: String,
    method: nip46::NostrConnectMethod,
    since: u64,
    signed_payload: Option<String>,
}

enum RequestOutcome {
    Response(nip46::NostrConnectResponse),
    Auth(String),
    Waiting,
}

enum ConnectOutcome {
    Ready(PublicKey),
    Auth(String),
    Waiting,
}

#[derive(serde::Deserialize)]
pub struct ConnectStart {
    bunker_uri: String,
}

#[derive(serde::Deserialize)]
pub struct ConnectContinue {
    connection: String,
}

#[derive(serde::Deserialize)]
pub struct SignRequest {
    unsigned_event: serde_json::Value,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn new_connection(uri: &str) -> Result<RemoteSigner, String> {
    let parsed = nip46::NostrConnectUri::parse(uri).map_err(|error| error.to_string())?;
    let nip46::NostrConnectUri::Bunker {
        remote_signer_public_key,
        relays,
        secret,
    } = parsed
    else {
        return Err("paste a bunker:// connection string from your remote signer".into());
    };
    if relays.is_empty() {
        return Err("the bunker connection string does not name a relay".into());
    }
    let client_keys = Keys::generate();
    // Request only the authority Apiary can exercise through its public API.
    // The server still independently enforces this kind allowlist.
    // NIP-46 positions permissions after the optional secret, so retain the
    // empty second parameter when the bunker URI does not include a secret.
    let mut params = vec![
        remote_signer_public_key.to_hex(),
        secret.unwrap_or_default(),
    ];
    params.push("sign_event:4600".into());
    params.push(
        json!({"name": "Apiary", "url": "https://github.com/farspeak-labs/apiary"}).to_string(),
    );
    let message = nip46::NostrConnectMessage::Request {
        id: random_token(),
        method: nip46::NostrConnectMethod::Connect,
        params,
    };
    let pending_connect = Some(publish_request(
        &client_keys,
        remote_signer_public_key,
        &relays.iter().map(ToString::to_string).collect::<Vec<_>>(),
        message,
        nip46::NostrConnectMethod::Connect,
    )?);
    Ok(RemoteSigner {
        client_keys,
        remote_signer: remote_signer_public_key,
        relays: relays.into_iter().map(|relay| relay.to_string()).collect(),
        user: None,
        stage: ConnectStage::Connect,
        pending_connect,
        pending_sign: None,
        created_at: now_secs(),
    })
}

fn publish_request(
    keys: &Keys,
    remote: PublicKey,
    relays: &[String],
    message: nip46::NostrConnectMessage,
    method: nip46::NostrConnectMethod,
) -> Result<PendingRequest, String> {
    let id = message.id().to_string();
    let event = nip46::NostrConnectEventBuilder::new(remote, message)
        .finalize(keys)
        .map_err(|error| format!("could not encrypt the signer request: {error}"))?;
    let mut errors = Vec::new();
    let mut published = false;
    for relay in relays {
        match apiary_runtime::relay::publish(relay, &event) {
            Ok(_) => published = true,
            Err(error) => errors.push(format!("{relay}: {error}")),
        }
    }
    if !published {
        return Err(format!(
            "could not publish to the signer relay: {}",
            errors.join("; ")
        ));
    }
    Ok(PendingRequest {
        id,
        method,
        since: event.created_at.as_secs().saturating_sub(2),
        signed_payload: None,
    })
}

fn inspect_responses(
    signer: &RemoteSigner,
    pending: &PendingRequest,
) -> Result<RequestOutcome, String> {
    let filter = json!({
        "kinds": [Kind::NostrConnect.as_u16()],
        "authors": [signer.remote_signer.to_hex()],
        "#p": [signer.client_keys.public_key().to_hex()],
        "since": pending.since,
        "limit": 64,
    });
    let mut auth_url = None;
    for relay in &signer.relays {
        let events = match apiary_runtime::relay::fetch(relay, filter.clone()) {
            Ok(events) => events,
            Err(_) => continue,
        };
        for event in events {
            if event.pubkey != signer.remote_signer || event.verify().is_err() {
                continue;
            }
            let plaintext = match nip44::decrypt(
                signer.client_keys.secret_key(),
                &signer.remote_signer,
                &event.content,
            ) {
                Ok(plaintext) => plaintext,
                Err(_) => continue,
            };
            let message = match nip46::NostrConnectMessage::from_json(plaintext) {
                Ok(message) if message.id() == pending.id => message,
                _ => continue,
            };
            let response = message
                .to_response(pending.method)
                .map_err(|error| format!("invalid response from remote signer: {error}"))?;
            if response.is_auth_url() {
                auth_url = response.error.clone();
                continue;
            }
            if let Some(error) = response.error.as_deref() {
                return Err(format!("remote signer refused the request: {error}"));
            }
            return Ok(RequestOutcome::Response(response));
        }
    }
    if let Some(url) = auth_url {
        Ok(RequestOutcome::Auth(url))
    } else {
        Ok(RequestOutcome::Waiting)
    }
}

fn drive_connection(signer: &mut RemoteSigner) -> Result<ConnectOutcome, String> {
    for _ in 0..2 {
        let pending = signer
            .pending_connect
            .clone()
            .ok_or_else(|| "remote signer connection has no pending request".to_string())?;
        match inspect_responses(signer, &pending)? {
            RequestOutcome::Auth(url) => return Ok(ConnectOutcome::Auth(url)),
            RequestOutcome::Waiting => return Ok(ConnectOutcome::Waiting),
            RequestOutcome::Response(response) => match signer.stage {
                ConnectStage::Connect => {
                    let result = response
                        .result
                        .ok_or_else(|| "remote signer returned no connect result".to_string())?;
                    if !matches!(
                        result,
                        nip46::ResponseResult::Ack | nip46::ResponseResult::ConnectSecret(_)
                    ) {
                        return Err("remote signer returned an unexpected connect response".into());
                    }
                    signer.stage = ConnectStage::PublicKey;
                    let request = nip46::NostrConnectRequest::GetPublicKey;
                    let message = nip46::NostrConnectMessage::request(&request);
                    signer.pending_connect = Some(publish_request(
                        &signer.client_keys,
                        signer.remote_signer,
                        &signer.relays,
                        message,
                        request.method(),
                    )?);
                }
                ConnectStage::PublicKey => {
                    let user = response
                        .result
                        .ok_or_else(|| "remote signer returned no public key".to_string())?
                        .to_get_public_key()
                        .map_err(|error| {
                            format!("remote signer returned an invalid public key: {error}")
                        })?;
                    signer.user = Some(user);
                    signer.stage = ConnectStage::Ready;
                    signer.pending_connect = None;
                    return Ok(ConnectOutcome::Ready(user));
                }
                ConnectStage::Ready => {
                    return signer
                        .user
                        .map(ConnectOutcome::Ready)
                        .ok_or_else(|| "remote signer lost its user identity".into())
                }
            },
        }
    }
    Ok(ConnectOutcome::Waiting)
}

fn random_token() -> String {
    Keys::generate().secret_key().to_secret_hex()
}

async fn connection_response(
    state: &App,
    signer: RemoteSigner,
    token: String,
) -> axum::response::Response {
    let driven = tokio::task::spawn_blocking(move || {
        let mut signer = signer;
        let outcome = drive_connection(&mut signer);
        (signer, outcome)
    })
    .await;
    let (signer, outcome) = match driven {
        Ok((signer, Ok(outcome))) => (signer, outcome),
        Ok((_, Err(error))) => return err(StatusCode::BAD_GATEWAY, error).into_response(),
        Err(error) => {
            return err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    };
    match outcome {
        ConnectOutcome::Auth(url) => {
            state
                .pending_nip46
                .lock()
                .ok()
                .map(|mut pending| pending.insert(token.clone(), signer));
            Json(json!({"ok": false, "pending": true, "connection": token, "auth_url": url}))
                .into_response()
        }
        ConnectOutcome::Waiting => {
            state
                .pending_nip46
                .lock()
                .ok()
                .map(|mut pending| pending.insert(token.clone(), signer));
            Json(json!({"ok": false, "pending": true, "connection": token})).into_response()
        }
        ConnectOutcome::Ready(user) => {
            if let Err(error) = nip98::authorize_cockpit(state, Some(user)) {
                return error.into_response();
            }
            state
                .remote_signers
                .lock()
                .ok()
                .map(|mut signers| signers.insert(user.to_hex(), signer));
            let secure = state.origin.starts_with("https://");
            ops::browser_session_response(state, user, secure)
        }
    }
}

/// Begin a bunker:// connection. This route is intentionally available
/// before login; completing the encrypted handshake is the authentication.
pub async fn connect_start(
    State(state): State<App>,
    Json(body): Json<ConnectStart>,
) -> axum::response::Response {
    if state.auth != AuthMode::Nip98 {
        return err(
            StatusCode::BAD_REQUEST,
            "remote sign-in is only used by private hosts",
        )
        .into_response();
    }
    let bunker_uri = body.bunker_uri.trim().to_string();
    if bunker_uri.len() > 4096 {
        return err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the bunker connection string is too long",
        )
        .into_response();
    }
    if let Ok(mut pending) = state.pending_nip46.lock() {
        let now = now_secs();
        pending.retain(|_, signer| now.saturating_sub(signer.created_at) < CONNECTION_TTL_SECS);
        if pending.len() >= 32 {
            return err(
                StatusCode::TOO_MANY_REQUESTS,
                "too many remote signer connections are pending",
            )
            .into_response();
        }
    }
    let token = random_token();
    let signer = match tokio::task::spawn_blocking(move || new_connection(&bunker_uri)).await {
        Ok(Ok(signer)) => signer,
        Ok(Err(error)) => return err(StatusCode::BAD_REQUEST, error).into_response(),
        Err(error) => {
            return err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    };
    connection_response(&state, signer, token).await
}

/// Poll a connection after the signer has shown an authorization URL.
pub async fn connect_continue(
    State(state): State<App>,
    Json(body): Json<ConnectContinue>,
) -> axum::response::Response {
    let signer = state.pending_nip46.lock().ok().and_then(|mut pending| {
        let now = now_secs();
        pending.retain(|_, signer| now.saturating_sub(signer.created_at) < CONNECTION_TTL_SECS);
        pending.remove(&body.connection)
    });
    let Some(signer) = signer else {
        return err(
            StatusCode::NOT_FOUND,
            "remote signer connection expired; start again",
        )
        .into_response();
    };
    connection_response(&state, signer, body.connection).await
}

fn sign_ratification(
    signer: &mut RemoteSigner,
    unsigned: &UnsignedEvent,
) -> Result<RequestOutcome, String> {
    if unsigned.kind != Kind::Custom(RATIFICATION_KIND) {
        return Err("NIP-46 signing is limited to Apiary ratification events".into());
    }
    let user = signer
        .user
        .ok_or_else(|| "remote signer is not ready".to_string())?;
    if unsigned.pubkey != user {
        return Err("the ratification event does not belong to this signer".into());
    }
    let unsigned_json = unsigned.as_json();
    let pending = if let Some(pending) = signer.pending_sign.clone() {
        if pending.signed_payload.as_deref() != Some(unsigned_json.as_str()) {
            return Err("another ratification is already awaiting the remote signer".into());
        }
        pending
    } else {
        let request = nip46::NostrConnectRequest::SignEvent(unsigned.clone());
        let message = nip46::NostrConnectMessage::request(&request);
        let mut pending = publish_request(
            &signer.client_keys,
            signer.remote_signer,
            &signer.relays,
            message,
            request.method(),
        )?;
        pending.signed_payload = Some(unsigned_json);
        signer.pending_sign = Some(pending.clone());
        pending
    };
    let outcome = inspect_responses(signer, &pending)?;
    if matches!(outcome, RequestOutcome::Response(_)) {
        signer.pending_sign = None;
    }
    Ok(outcome)
}

/// Ask the connected bunker to sign one kind-4600 ratification. This is not
/// a general signing endpoint.
pub async fn sign(
    State(state): State<App>,
    uri: axum::extract::OriginalUri,
    headers: axum::http::HeaderMap,
    Json(body): Json<SignRequest>,
) -> axum::response::Response {
    let pq = uri
        .0
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_else(|| uri.0.path().to_string());
    let user = match nip98::check(&state, &headers, "POST", &pq, None) {
        Ok(Some(user)) => user,
        Ok(None) => {
            return err(
                StatusCode::UNAUTHORIZED,
                "a signed-in Nostr identity is required",
            )
            .into_response()
        }
        Err(error) => return error.into_response(),
    };
    let unsigned = match UnsignedEvent::from_json(body.unsigned_event.to_string()) {
        Ok(unsigned) => unsigned,
        Err(error) => {
            return err(
                StatusCode::BAD_REQUEST,
                format!("invalid unsigned event: {error}"),
            )
            .into_response()
        }
    };
    let key = user.to_hex();
    let signer = state
        .remote_signers
        .lock()
        .ok()
        .and_then(|mut signers| signers.remove(&key));
    let Some(mut signer) = signer else {
        return err(
            StatusCode::CONFLICT,
            "connect this Nostr identity with NIP-46 first",
        )
        .into_response();
    };
    let unsigned_for_sign = unsigned.clone();
    let result = tokio::task::spawn_blocking(move || {
        let outcome = sign_ratification(&mut signer, &unsigned_for_sign);
        (signer, outcome)
    })
    .await;
    let (signer, outcome) = match result {
        Ok(value) => value,
        Err(error) => {
            return err(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    };
    state
        .remote_signers
        .lock()
        .ok()
        .map(|mut signers| signers.insert(key, signer));
    match outcome {
        Ok(RequestOutcome::Response(response)) => match response.result.and_then(|result| result.to_sign_event().ok()) {
            Some(event)
                if event.verify().is_ok()
                    && event.pubkey == unsigned.pubkey
                    && event.kind == unsigned.kind
                    && event.created_at == unsigned.created_at
                    && event.tags == unsigned.tags
                    && event.content == unsigned.content =>
                Json(json!({"ok": true, "event": serde_json::from_str::<serde_json::Value>(&event.as_json()).unwrap_or_default()})).into_response(),
            _ => err(StatusCode::BAD_GATEWAY, "remote signer returned an invalid ratification").into_response(),
        },
        Ok(RequestOutcome::Auth(url)) => (StatusCode::CONFLICT, Json(json!({"ok": false, "code": "nip46_auth_required", "auth_url": url}))).into_response(),
        Ok(RequestOutcome::Waiting) => (StatusCode::ACCEPTED, Json(json!({"ok": false, "pending": true}))).into_response(),
        Err(error) => err(StatusCode::BAD_GATEWAY, error).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bunker_uri_is_required_and_secret_is_not_rendered() {
        assert!(new_connection("nostrconnect://deadbeef").is_err());
        assert!(new_connection("https://example.com").is_err());
    }

    #[test]
    fn ratification_kind_is_the_only_remote_signing_kind() {
        let keys = Keys::generate();
        let unsigned = EventBuilder::new(Kind::TextNote, "no").finalize_unsigned(keys.public_key());
        let mut signer = RemoteSigner {
            client_keys: Keys::generate(),
            remote_signer: Keys::generate().public_key(),
            relays: vec![],
            user: Some(keys.public_key()),
            stage: ConnectStage::Ready,
            pending_connect: None,
            pending_sign: None,
            created_at: now_secs(),
        };
        assert!(sign_ratification(&mut signer, &unsigned).is_err());
    }
}
