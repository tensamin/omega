use super::super::connection::{
    OmikronConnection, OmikronResult, OptionalDataValueCompat, RequiredMtpFields,
};
use crate::db::user_repo;
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue},
    type_map::TypeMap,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

async fn send_error(
    connection: Arc<OmikronConnection>,
    request_id: u32,
    error_type: CommunicationType,
    session_id: Option<i128>,
) -> OmikronResult<()> {
    let mut response = CommunicationValue::new(error_type).with_id(request_id);
    if let Some(session_id) = session_id {
        response =
            response.add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id));
    }
    connection.send(&response).await
}

pub async fn get(
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
) -> OmikronResult<()> {
    let state = connection.state();
    let legacy_peer = !connection.peer_capabilities().client_state_push_v1;
    let Some(DataValue::Array(ids)) = value.get_data(DataType::UserIds) else {
        return send_error(
            connection,
            value.require_id()?,
            CommunicationType::ErrorInvalidData,
            None,
        )
        .await;
    };
    let session_id = value
        .get_data(DataType::SessionId)
        .as_number()
        .filter(|id| *id > 0);
    if session_id.is_none() && !legacy_peer {
        return send_error(
            connection,
            value.require_id()?,
            CommunicationType::ErrorInvalidData,
            None,
        )
        .await;
    }
    let tm = TypeMap::latest();
    let mut requested_user_ids = Vec::new();
    let mut requested_set = HashSet::new();
    for id in ids {
        let DataValue::SignedNumber(id) = id else {
            return send_error(
                connection,
                value.require_id()?,
                CommunicationType::ErrorInvalidData,
                session_id,
            )
            .await;
        };
        let Ok(user_id) = i64::try_from(*id) else {
            return send_error(
                connection,
                value.require_id()?,
                CommunicationType::ErrorInvalidData,
                session_id,
            )
            .await;
        };
        if user_id <= 0 {
            return send_error(
                connection,
                value.require_id()?,
                CommunicationType::ErrorInvalidData,
                session_id,
            )
            .await;
        }
        if !requested_set.insert(user_id) {
            continue;
        }
        requested_user_ids.push(user_id);
    }

    let boundary = state.presence.observation_boundary();
    let users = match user_repo::get_users_by_ids(&requested_user_ids).await {
        Ok(users) => users,
        Err(_) => {
            return send_error(
                connection,
                value.require_id()?,
                CommunicationType::ErrorInternal,
                session_id,
            )
            .await;
        }
    };
    let users_by_id: HashMap<_, _> = users.into_iter().map(|user| (user.id.0, user)).collect();
    let mut states = Vec::new();
    let mut missing_user_ids = Vec::new();
    for user_id in requested_user_ids {
        let Some(user) = users_by_id.get(&user_id) else {
            missing_user_ids.push(user_id);
            continue;
        };
        let (status, sequence) = state
            .presence
            .observe_public_state(user_id, user.iota_id.map(|id| id.0));
        let mut map = Vec::new();
        if let Some(kind) = DataType::UserId.try_to_id(&tm) {
            map.push((kind, DataValue::SignedNumber(user_id.into())));
        }
        if let Some(kind) = DataType::UserState.try_to_id(&tm) {
            map.push((kind, DataValue::Str(status.to_string())));
        }
        if let Some(kind) = DataType::VersionNumber.try_to_id(&tm) {
            map.push((kind, DataValue::UnsignedNumber(sequence.into())));
        }
        states.push(DataValue::Container(map));
    }
    let response = CommunicationValue::new(CommunicationType::GetStates)
        .with_id(value.require_id()?)
        .add_typed_default(
            DataType::Uuid,
            DataValue::Str(state.presence.observation_epoch.to_string()),
        )
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::UnsignedNumber(boundary.into()),
        )
        .add_typed_default(DataType::UserStates, DataValue::Array(states));
    let response = if let Some(session_id) = session_id {
        response.add_typed_default(DataType::SessionId, DataValue::SignedNumber(session_id))
    } else {
        response
    };
    let response = if legacy_peer {
        response
    } else {
        response.add_typed_default(
            DataType::MissingUserIds,
            DataValue::Array(
                missing_user_ids
                    .into_iter()
                    .map(|id| DataValue::SignedNumber(id.into()))
                    .collect(),
            ),
        )
    };
    connection.send(&response).await
}
