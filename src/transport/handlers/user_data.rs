use super::super::connection::{
    OmikronConnection, OmikronResult, OptionalDataValueCompat, RequiredMtpFields,
};
use crate::{
    db::{iota_repo, user_repo},
    error::OmegaError,
    models::{IotaId, UserId},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue},
    crypto::PublicKeyBundle,
};
use std::sync::Arc;

const MAX_DISPLAY_BYTES: usize = 255;
const MAX_STATUS_BYTES: usize = 255;
const MAX_ABOUT_BYTES: usize = 1000;
const MAX_AVATAR_BYTES: usize = 65_535;

fn missing_as_none<T>(value: OmikronResult<T>) -> OmikronResult<Option<T>> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(OmegaError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

fn connections(connection: &OmikronConnection, iota_id: i64) -> DataValue {
    DataValue::Array(
        connection
            .state()
            .presence
            .iota_connections(iota_id)
            .unwrap_or_default()
            .into_iter()
            .map(|id| DataValue::SignedNumber(id.into()))
            .collect(),
    )
}

pub async fn get_user(
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
) -> OmikronResult<()> {
    let request_id = value.require_id()?;
    let sender = value.require_sender_i64()?;
    let state = connection.state();
    let user = if let Some(id) = value
        .get_data(DataType::UserId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    {
        missing_as_none(user_repo::get_by_user_id(UserId::from(id)).await)?
    } else if let Some(name) = value.get_data(DataType::Username).as_str() {
        missing_as_none(user_repo::get_by_username(name).await)?
    } else {
        None
    };
    let Some(user) = user else {
        return connection
            .send_error_response(request_id, CommunicationType::ErrorNotFound)
            .await;
    };
    let id = user.id.0;
    let signed_descriptor =
        crate::server::api::federation_user_descriptor(user.clone(), &state.identity).await;
    let iota_id = user.iota_id.map(|id| id.0);
    let username = user.username.clone();
    let display = user
        .display
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| username.clone());
    let mut response = CommunicationValue::new(CommunicationType::GetUserData)
        .with_id(request_id)
        .add_typed_default(DataType::Username, DataValue::Str(username))
        .add_typed_default(
            DataType::PublicKey,
            DataValue::Str(user.public_key.try_to_base64()?),
        )
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(id.into()))
        .add_typed_default(
            DataType::Principal,
            DataValue::Str(format!(
                "{}#{id}",
                iota_identity::AuthorityId::for_omega(&state.identity.public_key_bundle())
                    .map_err(|error| OmegaError::Validation(error.to_string()))?
                    .as_str()
            )),
        )
        .add_typed_default(
            DataType::CreatedAt,
            DataValue::SignedNumber(user.created_at.into()),
        )
        .add_typed_default(DataType::Display, DataValue::Str(display))
        .add_typed_default(
            DataType::SubLevel,
            DataValue::SignedNumber(user.sub_level as i128),
        )
        .add_typed_default(
            DataType::SubEnd,
            DataValue::SignedNumber(user.sub_end.into()),
        );
    if let Ok(descriptor) = signed_descriptor {
        response = response
            .add_typed_default(
                DataType::Json,
                DataValue::Bytes(
                    serde_json::to_vec(&descriptor)
                        .map_err(|error| OmegaError::Validation(error.to_string()))?,
                ),
            )
            .add_typed_default(
                DataType::PublicKeys,
                DataValue::Str(state.identity.public_key_bundle().try_to_base64()?),
            );
    }
    if let Some(status) = user.status.filter(|value| !value.is_empty()) {
        response = response.add_typed_default(DataType::Status, DataValue::Str(status));
    }
    if let Some(about) = user.about.filter(|value| !value.is_empty()) {
        response = response.add_typed_default(DataType::About, DataValue::Str(about));
    }
    if let Some(avatar) = user.avatar {
        response =
            response.add_typed_default(DataType::Avatar, DataValue::Str(STANDARD.encode(avatar)));
    }
    let route = state.presence.user_route(id);
    let private_request = sender == id && state.presence.owns_user_route(id, connection.id_i64());
    let resolved_status = if private_request {
        if !state
            .presence
            .load_preference(id, &user.presence_preference)
        {
            crate::log_in!(
                crate::util::logger::PrintType::General,
                "Invalid persisted presence preference for user {}, using user_online",
                id
            );
        }
        state.presence.resolve_private_state(id)
    } else {
        iota_id
            .map(|iota_id| state.presence.resolve_public_state(id, iota_id))
            .unwrap_or(crate::sql::connection_status::UserStatus::user_offline)
    };
    response = response
        .add_typed_default(
            DataType::OnlineStatus,
            DataValue::Str(resolved_status.to_string()),
        )
        .add_typed_default(
            DataType::OmikronConnections,
            iota_id
                .map(|iota_id| connections(&connection, iota_id))
                .unwrap_or_else(|| DataValue::Array(Vec::new())),
        );
    if let Some(iota_id) = iota_id {
        response =
            response.add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()));
    }
    if let Some(route) = route {
        response = response.add_typed_default(
            DataType::OmikronId,
            DataValue::SignedNumber(route.omikron_id.into()),
        );
    }
    connection.send(&response).await
}

pub async fn get_iota(
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
) -> OmikronResult<()> {
    let request_id = value.require_id()?;
    let found = if let Some(id) = value
        .get_data(DataType::IotaId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    {
        missing_as_none(iota_repo::get_iota_by_id(IotaId::from(id)).await)?
            .map(|iota| (iota.id.0, iota.public_key, None, None))
    } else if let Some(id) = value.get_data(DataType::UserId).as_number() {
        if let Some(id) = i64::try_from(id).ok().filter(|id| *id > 0)
            && let Ok(user) = user_repo::get_by_user_id(UserId::from(id)).await
        {
            match user.iota_id {
                Some(iota_id) => missing_as_none(iota_repo::get_iota_by_id(iota_id).await)?
                    .map(|iota| (iota.id.0, iota.public_key, Some(user.id.0), None)),
                None => None,
            }
        } else {
            None
        }
    } else if let Some(name) = value.get_data(DataType::Username).as_str() {
        if let Some(user) = missing_as_none(user_repo::get_by_username(name).await)? {
            match user.iota_id {
                Some(iota_id) => {
                    missing_as_none(iota_repo::get_iota_by_id(iota_id).await)?.map(|iota| {
                        (
                            iota.id.0,
                            iota.public_key,
                            Some(user.id.0),
                            Some(name.to_owned()),
                        )
                    })
                }
                None => None,
            }
        } else {
            None
        }
    } else {
        None
    };
    let Some((id, key, user_id, username)) = found else {
        return connection
            .send_error_response(request_id, CommunicationType::ErrorNotFound)
            .await;
    };
    let mut response = CommunicationValue::new(CommunicationType::GetIotaData)
        .with_id(request_id)
        .add_typed_default(DataType::PublicKey, DataValue::Str(key.try_to_base64()?))
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(id.into()))
        .add_typed_default(DataType::OmikronConnections, connections(&connection, id));
    if let Some(user_id) = user_id {
        response =
            response.add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
    }
    if let Some(username) = username {
        response = response.add_typed_default(DataType::Username, DataValue::Str(username));
    }
    connection.send(&response).await
}

fn optional_string(
    value: &CommunicationValue,
    data_type: DataType,
    max_bytes: usize,
    field: &'static str,
) -> Result<Option<String>, OmegaError> {
    let Some(value) = value.get_data(data_type) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| OmegaError::Validation(format!("invalid {field}")))?;
    if value.len() > max_bytes {
        return Err(OmegaError::Validation(format!("{field} is too long")));
    }
    Ok(Some(value.to_owned()))
}

fn parse_user_patch(value: &CommunicationValue) -> Result<user_repo::UserPatch, OmegaError> {
    let username = optional_string(value, DataType::Username, 15, "username")?;
    if username
        .as_deref()
        .is_some_and(|username| !user_repo::valid_username(username))
    {
        return Err(OmegaError::Validation("invalid username".into()));
    }
    let avatar = match value.get_data(DataType::Avatar) {
        None => None,
        Some(value) => {
            let encoded = value
                .as_str()
                .ok_or_else(|| OmegaError::Validation("invalid avatar".into()))?;
            let decoded = STANDARD
                .decode(encoded)
                .map_err(|_| OmegaError::Validation("invalid avatar".into()))?;
            if decoded.len() > MAX_AVATAR_BYTES {
                return Err(OmegaError::Validation("avatar is too large".into()));
            }
            Some(decoded)
        }
    };
    let public_key = match value.get_data(DataType::PublicKey) {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| OmegaError::Validation("invalid public key".into()))
                .and_then(|encoded| {
                    PublicKeyBundle::from_base64(encoded)
                        .map_err(|_| OmegaError::Validation("invalid public key".into()))
                })?,
        ),
    };
    let presence_preference = match value.get_data(DataType::OnlineStatus) {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(crate::sql::connection_status::UserStatus::from_client_preference)
                .ok_or_else(|| OmegaError::Validation("invalid online status".into()))?,
        ),
    };

    Ok(user_repo::UserPatch {
        username,
        display: optional_string(value, DataType::Display, MAX_DISPLAY_BYTES, "display")?,
        avatar,
        about: optional_string(value, DataType::About, MAX_ABOUT_BYTES, "about")?,
        status: optional_string(value, DataType::Status, MAX_STATUS_BYTES, "status")?,
        public_key,
        presence_preference,
    })
}

fn user_patch_error_type(error: &OmegaError) -> CommunicationType {
    match error {
        OmegaError::Validation(_) => CommunicationType::ErrorInvalidData,
        OmegaError::NotFound => CommunicationType::ErrorNotFound,
        _ => CommunicationType::ErrorInternal,
    }
}

pub async fn change_user(
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
) -> OmikronResult<()> {
    let request_id = value.require_id()?;
    let id = UserId::from(value.require_sender_i64()?);
    let patch = match parse_user_patch(&value) {
        Ok(patch) => patch,
        Err(error @ OmegaError::Validation(_)) => {
            return connection
                .send_error_response(request_id, user_patch_error_type(&error))
                .await;
        }
        Err(error) => return Err(error),
    };
    let user = if patch.presence_preference.is_some() {
        match user_repo::get_by_user_id(id).await {
            Ok(user) => Some(user),
            Err(OmegaError::NotFound) => {
                return connection
                    .send_error_response(request_id, CommunicationType::ErrorNotFound)
                    .await;
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    if let Err(error) = user_repo::update_user_patch(id, &patch).await {
        return connection
            .send_error_response(request_id, user_patch_error_type(&error))
            .await;
    }
    if let (Some(user), Some(preference)) = (user, patch.presence_preference) {
        super::presence::apply_committed_preference(&connection.state(), &user, preference).await;
    }
    connection
        .send(&CommunicationValue::new(CommunicationType::Success).with_id(request_id))
        .await
}

#[cfg(test)]
mod tests {
    use super::{parse_user_patch, user_patch_error_type};
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

    #[test]
    fn rejects_invalid_fields_before_building_patch() {
        let invalid_username = CommunicationValue::new(CommunicationType::ChangeUserData)
            .add_typed_default(DataType::Username, DataValue::Str("Invalid".into()));
        let invalid_key = CommunicationValue::new(CommunicationType::ChangeUserData)
            .add_typed_default(DataType::PublicKey, DataValue::Str("not-a-key".into()));

        assert!(parse_user_patch(&invalid_username).is_err());
        let error = parse_user_patch(&invalid_key).unwrap_err();
        assert_eq!(
            user_patch_error_type(&error),
            CommunicationType::ErrorInvalidData
        );
    }

    #[test]
    fn parses_profile_and_presence_as_one_patch() {
        let value = CommunicationValue::new(CommunicationType::ChangeUserData)
            .add_typed_default(DataType::Display, DataValue::Str("Alex".into()))
            .add_typed_default(
                DataType::OnlineStatus,
                DataValue::Str("user_invisible".into()),
            );

        let patch = parse_user_patch(&value).unwrap();
        assert_eq!(patch.display.as_deref(), Some("Alex"));
        assert_eq!(
            patch.presence_preference.map(|value| value.to_string()),
            Some("user_invisible".into())
        );
    }
}
