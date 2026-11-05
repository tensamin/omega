use super::super::connection::{
    OmikronConnection, OmikronResult, OptionalDataValueCompat, RequiredMtpFields,
};
use crate::{
    db::{iota_repo, user_repo},
    error::OmegaError,
    log_in,
    models::IotaId,
    sql::connection_status::UserStatus,
    state::OmegaState,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

fn parse_subscription(value: &CommunicationValue) -> Result<(i64, i64, Vec<i64>), &'static str> {
    let Some(sender) = value.sender() else {
        return Err("user_id");
    };
    let user_id = i64::try_from(sender)
        .ok()
        .filter(|id| *id > 0)
        .ok_or("user_id")?;
    let session_id = value
        .get_data(DataType::SessionId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
        .ok_or("session_id")?;
    let Some(DataValue::Array(values)) = value.get_data(DataType::UserIds) else {
        return Err("user_ids");
    };

    let mut user_ids = Vec::with_capacity(values.len());
    for value in values {
        let DataValue::SignedNumber(user_id) = value else {
            return Err("user_ids");
        };
        let Ok(user_id) = i64::try_from(*user_id) else {
            return Err("user_ids");
        };
        if user_id <= 0 {
            return Err("user_ids");
        }
        if !user_ids.contains(&user_id) {
            user_ids.push(user_id);
        }
    }
    Ok((user_id, session_id, user_ids))
}

fn apply_preferences(state: &OmegaState, preferences: HashMap<i64, UserStatus>) {
    state.presence.set_preferences(preferences);
}

fn states_for_users(state: &OmegaState, users: &[crate::models::User]) -> HashMap<i64, UserStatus> {
    users
        .iter()
        .map(|user| {
            let status = user
                .iota_id
                .map(|iota_id| state.presence.resolve_public_state(user.id.0, iota_id.0))
                .unwrap_or(UserStatus::user_offline);
            (user.id.0, status)
        })
        .collect()
}

fn states_before_route_removal(
    state: &OmegaState,
    users: &[crate::models::User],
    removed_iota_ids: &HashSet<i64>,
    removed_session_user_ids: &HashSet<i64>,
) -> HashMap<i64, UserStatus> {
    users
        .iter()
        .map(|user| {
            let current = user
                .iota_id
                .map(|iota_id| state.presence.resolve_public_state(user.id.0, iota_id.0))
                .unwrap_or(UserStatus::user_offline);
            let previous = if removed_session_user_ids.contains(&user.id.0) {
                state.presence.preference(user.id.0).public_value()
            } else if user
                .iota_id
                .is_some_and(|iota_id| removed_iota_ids.contains(&iota_id.0))
                && current == UserStatus::iota_offline
            {
                UserStatus::user_offline
            } else {
                current
            };
            (user.id.0, previous)
        })
        .collect()
}

async fn publish_route_removal(
    state: &OmegaState,
    user_ids: &[i64],
    iota_ids: &[i64],
    removed_session_user_ids: &HashSet<i64>,
    context: &str,
) {
    let users = match user_repo::get_users_by_ids_and_iota_ids(user_ids, iota_ids).await {
        Ok(users) => users,
        Err(error) => {
            log_in!(
                crate::util::logger::PrintType::General,
                "Failed to load users after {} route cleanup: {}",
                context,
                error
            );
            return;
        }
    };
    let user_ids = users.iter().map(|user| user.id.0).collect::<Vec<_>>();
    let preferences = match user_repo::get_presence_preferences(&user_ids).await {
        Ok(preferences) => preferences,
        Err(error) => {
            log_in!(
                crate::util::logger::PrintType::General,
                "Failed to load preferences after {} route cleanup: {}",
                context,
                error
            );
            return;
        }
    };
    apply_preferences(state, preferences);
    let removed_iota_ids = iota_ids.iter().copied().collect::<HashSet<_>>();
    let before =
        states_before_route_removal(state, &users, &removed_iota_ids, removed_session_user_ids);
    publish_changed_states(state, &before, &users).await;
}

fn changed_states(
    state: &OmegaState,
    before: &HashMap<i64, UserStatus>,
    users: &[crate::models::User],
) -> Vec<(i64, UserStatus, u64)> {
    let mut changes = users
        .iter()
        .filter_map(|user| {
            let (after, sequence) = state
                .presence
                .observe_public_state(user.id.0, user.iota_id.map(|id| id.0));
            (before.get(&user.id.0) != Some(&after)).then_some((user.id.0, after, sequence))
        })
        .collect::<Vec<_>>();
    changes.sort_by_key(|(user_id, _, _)| *user_id);
    changes.dedup_by_key(|(user_id, _, _)| *user_id);
    changes
}

fn state_notification(
    subscriber: &crate::sql::user_online_tracker::PresenceSubscriber,
    user_id: i64,
    user_state: &UserStatus,
    epoch: uuid::Uuid,
    sequence: u64,
) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::ClientChanged)
        .with_receiver(subscriber.user_id as u64)
        .add_typed_default(
            DataType::SessionId,
            DataValue::SignedNumber(subscriber.session_id.into()),
        )
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()))
        .add_typed_default(DataType::UserState, DataValue::Str(user_state.to_string()))
        .add_typed_default(DataType::Uuid, DataValue::Str(epoch.to_string()))
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::UnsignedNumber(sequence.into()),
        )
}

async fn publish_state_changes(state: &OmegaState, changes: &[(i64, UserStatus, u64)]) {
    let mut grouped = BTreeMap::<i64, Vec<CommunicationValue>>::new();
    for (user_id, user_state, sequence) in changes {
        for subscriber in state.presence.subscribers(*user_id) {
            grouped
                .entry(subscriber.omikron_id)
                .or_default()
                .push(state_notification(
                    &subscriber,
                    *user_id,
                    user_state,
                    state.presence.observation_epoch,
                    *sequence,
                ));
        }
    }
    for (omikron_id, notifications) in grouped {
        if let Err(error) =
            crate::transport::omikron_manager::send_state_batch(state, omikron_id, notifications)
                .await
        {
            log_in!(
                crate::util::logger::PrintType::General,
                "Failed to deliver presence state batch to Omikron {}: {}",
                omikron_id,
                error
            );
        }
    }
}

async fn publish_changed_states(
    state: &OmegaState,
    before: &HashMap<i64, UserStatus>,
    users: &[crate::models::User],
) {
    publish_state_changes(state, &changed_states(state, before, users)).await;
}

pub(crate) async fn apply_committed_preference(
    state: &OmegaState,
    user: &crate::models::User,
    preference: UserStatus,
) {
    let users = std::slice::from_ref(user);
    let before = states_for_users(state, users);
    state.presence.set_preference(user.id.0, preference);
    publish_changed_states(state, &before, users).await;
}

pub async fn state_subscribe(
    state: Arc<OmegaState>,
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
    omikron_id: i64,
) -> OmikronResult<()> {
    let (user_id, session_id, user_ids) = match parse_subscription(&value) {
        Ok(subscription) => subscription,
        Err("user_id") => {
            return connection
                .send_error_response(value.require_id()?, CommunicationType::ErrorNoUserId)
                .await;
        }
        Err(detail) => {
            return connection
                .send_error_response_with_detail(
                    value.require_id()?,
                    CommunicationType::ErrorInvalidData,
                    detail,
                )
                .await;
        }
    };
    if !state.presence.owns_session(user_id, session_id, omikron_id) {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorNoIota)
            .await;
    }
    state
        .presence
        .replace_subscription(user_id, session_id, omikron_id, user_ids);
    connection
        .send(&CommunicationValue::new(CommunicationType::Success).with_id(value.require_id()?))
        .await
}

pub async fn client_changed_legacy(
    state: Arc<OmegaState>,
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
    _: i64,
) -> OmikronResult<()> {
    let request_id = value.require_id()?;
    let user_id = value.require_sender_i64()?;
    let Some(status) = value
        .get_data(DataType::UserState)
        .as_str()
        .and_then(UserStatus::from_client_preference)
    else {
        return connection
            .send_error_response(request_id, CommunicationType::ErrorInvalidData)
            .await;
    };
    let user = user_repo::get_by_user_id(user_id.into()).await?;
    user_repo::update_user_patch(
        user.id,
        &user_repo::UserPatch {
            presence_preference: Some(status.clone()),
            ..Default::default()
        },
    )
    .await?;
    apply_committed_preference(&state, &user, status).await;
    connection
        .send(&CommunicationValue::new(CommunicationType::Success).with_id(request_id))
        .await
}

pub async fn user_connected(
    state: Arc<OmegaState>,
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
    omikron_id: i64,
) -> OmikronResult<()> {
    let Some(user_id) = value
        .get_data(DataType::UserId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    else {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorInvalidData)
            .await;
    };
    let Some(session_id) = value
        .get_data(DataType::SessionId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    else {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorInvalidData)
            .await;
    };
    let Some(iota_id) = value
        .get_data(DataType::IotaId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    else {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorInvalidData)
            .await;
    };
    let user = match user_repo::get_by_user_id(user_id.into()).await {
        Ok(user) => user,
        Err(crate::error::OmegaError::NotFound) => {
            return connection
                .send_error_response(value.require_id()?, CommunicationType::ErrorNotFound)
                .await;
        }
        Err(error) => return Err(error),
    };
    let preferences = match user_repo::get_presence_preferences(&[user_id]).await {
        Ok(preferences) => preferences,
        Err(error) => return Err(error),
    };
    if user.iota_id.map(|id| id.0) != Some(iota_id)
        || !state.presence.owns_iota_route(iota_id, omikron_id)
    {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorNoIota)
            .await;
    }
    apply_preferences(&state, preferences);
    let users = [user];
    let before = states_for_users(&state, &users);
    state
        .presence
        .track_session(user_id, session_id, omikron_id, iota_id);
    crate::log_event!(
        omikron_id,
        crate::util::logger::PrintType::Omega,
        crate::util::logger::LogLevel::Info,
        "presence.user_connected",
        "request_id={} user_id={} session_id={} iota_id={} omikron_id={}",
        value.require_id()?,
        user_id,
        session_id,
        iota_id,
        omikron_id
    );
    publish_changed_states(&state, &before, &users).await;
    connection
        .send(&CommunicationValue::new(CommunicationType::Success).with_id(value.require_id()?))
        .await
}

pub async fn user_disconnected(
    state: Arc<OmegaState>,
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
    omikron_id: i64,
) -> OmikronResult<()> {
    let Some(user_id) = value
        .get_data(DataType::UserId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    else {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorInvalidData)
            .await;
    };
    let Some(session_id) = value
        .get_data(DataType::SessionId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    else {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorInvalidData)
            .await;
    };
    if let Ok(user) = user_repo::get_by_user_id(user_id.into()).await {
        let preferences = user_repo::get_presence_preferences(&[user_id]).await?;
        apply_preferences(&state, preferences);
        let users = [user];
        let before = states_for_users(&state, &users);
        state
            .presence
            .remove_session(user_id, session_id, omikron_id);
        publish_changed_states(&state, &before, &users).await;
    } else {
        state
            .presence
            .remove_session(user_id, session_id, omikron_id);
    }
    crate::log_event!(
        omikron_id,
        crate::util::logger::PrintType::Omega,
        crate::util::logger::LogLevel::Info,
        "presence.user_disconnected",
        "request_id={} user_id={} session_id={} omikron_id={}",
        value.require_id()?,
        user_id,
        session_id,
        omikron_id
    );
    connection
        .send(&CommunicationValue::new(CommunicationType::Success).with_id(value.require_id()?))
        .await
}

pub async fn iota_connected(
    state: Arc<OmegaState>,
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
    omikron_id: i64,
) -> OmikronResult<()> {
    let Some(iota_id) = value
        .get_data(DataType::IotaId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    else {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorInvalidData)
            .await;
    };
    let iota_id = IotaId::from(iota_id);
    match iota_repo::get_iota_by_id(iota_id).await {
        Ok(_) => {}
        Err(OmegaError::NotFound) => {
            return connection
                .send_error_response(value.require_id()?, CommunicationType::ErrorNotFound)
                .await;
        }
        Err(error) => return Err(error),
    }
    let users = user_repo::get_users_by_iota_id(iota_id).await?;
    let ids = users.iter().map(|user| user.id.0).collect::<Vec<_>>();
    apply_preferences(&state, user_repo::get_presence_preferences(&ids).await?);
    let before = states_for_users(&state, &users);
    state.presence.connect_iota(iota_id.0, omikron_id);
    crate::log_event!(
        omikron_id,
        crate::util::logger::PrintType::Omega,
        crate::util::logger::LogLevel::Info,
        "presence.iota_connected",
        "request_id={} iota_id={} omikron_id={}",
        value.require_id()?,
        iota_id.0,
        omikron_id
    );
    let user_ids = users
        .iter()
        .map(|user| DataValue::SignedNumber(user.id.0.into()))
        .collect();
    let response = CommunicationValue::new(CommunicationType::Success)
        .with_id(value.require_id()?)
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.0.into()))
        .add_typed_default(DataType::UserIds, DataValue::Array(user_ids));
    crate::transport::omikron_manager::deliver_pending_erasures(&state, iota_id.0).await;
    crate::transport::omikron_manager::deliver_pending_user_provisioning(&state, iota_id.0).await;
    publish_changed_states(&state, &before, &users).await;
    connection.send(&response).await
}

pub async fn iota_disconnected(
    state: Arc<OmegaState>,
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
    omikron_id: i64,
) -> OmikronResult<()> {
    let Some(iota_id) = value
        .get_data(DataType::IotaId)
        .as_number()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
    else {
        return connection
            .send_error_response(value.require_id()?, CommunicationType::ErrorInvalidData)
            .await;
    };
    let removed_session_user_ids = state
        .presence
        .sessions_owned_by(omikron_id)
        .into_iter()
        .filter_map(|(user_id, _, route)| (route.iota_id == iota_id).then_some(user_id))
        .collect::<HashSet<_>>();
    state.presence.untrack_iota_connection(iota_id, omikron_id);
    crate::log_event!(
        omikron_id,
        crate::util::logger::PrintType::Omega,
        crate::util::logger::LogLevel::Info,
        "presence.iota_disconnected",
        "request_id={} iota_id={} omikron_id={}",
        value.require_id()?,
        iota_id,
        omikron_id
    );
    publish_route_removal(
        &state,
        &removed_session_user_ids.iter().copied().collect::<Vec<_>>(),
        &[iota_id],
        &removed_session_user_ids,
        "Iota disconnect",
    )
    .await;
    connection
        .send(&CommunicationValue::new(CommunicationType::Success).with_id(value.require_id()?))
        .await
}

pub async fn sync_status(
    state: Arc<OmegaState>,
    connection: Arc<OmikronConnection>,
    value: CommunicationValue,
    omikron_id: i64,
) -> OmikronResult<()> {
    let request_id = value.require_id()?;
    let Some(DataValue::Array(iota_values)) = value.get_data(DataType::IotaIds) else {
        return connection
            .send_error_response(request_id, CommunicationType::ErrorInvalidData)
            .await;
    };
    let Some(DataValue::Array(session_values)) = value.get_data(DataType::UserStates) else {
        return connection
            .send_error_response(request_id, CommunicationType::ErrorInvalidData)
            .await;
    };

    let mut iota_ids = Vec::with_capacity(iota_values.len());
    for item in iota_values {
        let DataValue::SignedNumber(id) = item else {
            return connection
                .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                .await;
        };
        let Ok(id) = i64::try_from(*id) else {
            return connection
                .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                .await;
        };
        if id <= 0 {
            return connection
                .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                .await;
        }
        if !iota_ids.contains(&id) {
            iota_ids.push(id);
        }
    }

    if !connection.peer_capabilities().session_snapshot_v1 {
        let Some(DataValue::Array(user_values)) = value.get_data(DataType::UserIds) else {
            return connection
                .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                .await;
        };
        let mut user_ids = Vec::with_capacity(user_values.len());
        for item in user_values {
            let DataValue::SignedNumber(user_id) = item else {
                return connection
                    .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                    .await;
            };
            let Ok(user_id) = i64::try_from(*user_id) else {
                return connection
                    .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                    .await;
            };
            if user_id <= 0 {
                return connection
                    .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                    .await;
            }
            if !user_ids.contains(&user_id) {
                user_ids.push(user_id);
            }
        }

        let removed = state.presence.remove_omikron(omikron_id);
        let previous_iota_ids = removed.iota_ids;
        let affected_iota_ids = previous_iota_ids
            .iter()
            .chain(iota_ids.iter())
            .copied()
            .collect::<HashSet<_>>();
        let users = user_repo::get_users_by_ids(&user_ids).await?;
        let returned_user_ids = users.iter().map(|user| user.id.0).collect::<Vec<_>>();
        let affected_users = user_repo::get_users_by_ids_and_iota_ids(
            &returned_user_ids,
            &affected_iota_ids.iter().copied().collect::<Vec<_>>(),
        )
        .await?;
        apply_preferences(
            &state,
            user_repo::get_presence_preferences(
                &affected_users
                    .iter()
                    .map(|user| user.id.0)
                    .collect::<Vec<_>>(),
            )
            .await?,
        );
        let removed_iota_ids = previous_iota_ids.iter().copied().collect::<HashSet<_>>();
        let removed_session_user_ids = removed
            .session_user_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let before = states_before_route_removal(
            &state,
            &affected_users,
            &removed_iota_ids,
            &removed_session_user_ids,
        );
        state
            .presence
            .replace_omikron_snapshot(omikron_id, &iota_ids, &[]);
        publish_changed_states(&state, &before, &affected_users).await;
        return connection
            .send(&CommunicationValue::new(CommunicationType::Success).with_id(request_id))
            .await;
    }

    let tm = mtp::type_map::TypeMap::latest();
    let mut sessions = Vec::with_capacity(session_values.len());
    for item in session_values {
        let (user_id, session_id, iota_id) = if connection.peer_capabilities().session_snapshot_v1 {
            let DataValue::Container(entries) = item else {
                return connection
                    .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                    .await;
            };
            let find = |kind| {
                entries.iter().find_map(|(key, value)| {
                    (Some(*key) == DataType::try_to_id(kind, &tm)).then_some(value)
                })
            };
            let (
                Some(DataValue::SignedNumber(user_id)),
                Some(DataValue::SignedNumber(session_id)),
                Some(DataValue::SignedNumber(iota_id)),
            ) = (
                find(DataType::UserId),
                find(DataType::SessionId),
                find(DataType::IotaId),
            )
            else {
                return connection
                    .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                    .await;
            };
            (*user_id, *session_id, *iota_id)
        } else {
            let DataValue::Array(values) = item else {
                return connection
                    .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                    .await;
            };
            let [
                DataValue::SignedNumber(user_id),
                DataValue::SignedNumber(session_id),
                DataValue::SignedNumber(iota_id),
            ] = values.as_slice()
            else {
                return connection
                    .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                    .await;
            };
            (*user_id, *session_id, *iota_id)
        };
        let (Ok(user_id), Ok(session_id), Ok(iota_id)) = (
            i64::try_from(user_id),
            i64::try_from(session_id),
            i64::try_from(iota_id),
        ) else {
            return connection
                .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                .await;
        };
        if user_id <= 0 || session_id <= 0 || iota_id <= 0 || !iota_ids.contains(&iota_id) {
            return connection
                .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                .await;
        }
        if sessions.iter().any(|(existing_user, existing_session, _)| {
            *existing_user == user_id && *existing_session == session_id
        }) {
            return connection
                .send_error_response(request_id, CommunicationType::ErrorInvalidData)
                .await;
        }
        sessions.push((user_id, session_id, iota_id));
    }

    let removed = state.presence.remove_omikron(omikron_id);
    let previous_iota_ids = removed.iota_ids.clone();
    let previous_session_user_ids = removed
        .session_user_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let new_session_user_ids = sessions
        .iter()
        .map(|(user_id, _, _)| *user_id)
        .collect::<HashSet<_>>();
    let affected_iota_ids = previous_iota_ids
        .iter()
        .chain(iota_ids.iter())
        .copied()
        .collect::<HashSet<_>>();
    let users = user_repo::get_users_by_ids_and_iota_ids(
        &previous_session_user_ids
            .iter()
            .chain(new_session_user_ids.iter())
            .copied()
            .collect::<Vec<_>>(),
        &affected_iota_ids.iter().copied().collect::<Vec<_>>(),
    )
    .await?;
    if sessions.iter().any(|(user_id, _, iota_id)| {
        !users
            .iter()
            .any(|user| user.id.0 == *user_id && user.iota_id == Some(IotaId::from(*iota_id)))
    }) {
        return connection
            .send_error_response(request_id, CommunicationType::ErrorInvalidData)
            .await;
    }
    let user_ids = users.iter().map(|user| user.id.0).collect::<Vec<_>>();
    apply_preferences(
        &state,
        user_repo::get_presence_preferences(&user_ids).await?,
    );
    let before = states_before_route_removal(
        &state,
        &users,
        &previous_iota_ids.iter().copied().collect(),
        &previous_session_user_ids,
    );
    state
        .presence
        .replace_omikron_snapshot(omikron_id, &iota_ids, &sessions);
    publish_changed_states(&state, &before, &users).await;
    connection
        .send(&CommunicationValue::new(CommunicationType::Success).with_id(request_id))
        .await
}

pub async fn omikron_disconnected(state: Arc<OmegaState>, omikron_id: i64) {
    let removed = state.presence.remove_omikron(omikron_id);
    let removed_session_user_ids = removed
        .session_user_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    publish_route_removal(
        &state,
        &removed.session_user_ids,
        &removed.iota_ids,
        &removed_session_user_ids,
        &format!("Omikron {omikron_id} disconnect"),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::parse_subscription;
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

    fn request(user_ids: DataValue) -> CommunicationValue {
        CommunicationValue::new(CommunicationType::StateSubscribe)
            .with_sender(7)
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11))
            .add_typed_default(DataType::UserIds, user_ids)
    }

    #[test]
    fn subscription_parser_deduplicates_valid_targets() {
        let parsed = parse_subscription(&request(DataValue::Array(vec![
            DataValue::SignedNumber(20),
            DataValue::SignedNumber(21),
            DataValue::SignedNumber(20),
        ])))
        .unwrap();
        assert_eq!(parsed, (7, 11, vec![20, 21]));
    }

    #[test]
    fn subscription_parser_rejects_missing_or_malformed_fields() {
        let missing_users = CommunicationValue::new(CommunicationType::StateSubscribe)
            .with_sender(7)
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11));
        assert_eq!(parse_subscription(&missing_users), Err("user_ids"));

        let malformed_users = request(DataValue::Array(vec![DataValue::Str("bad".into())]));
        assert_eq!(parse_subscription(&malformed_users), Err("user_ids"));

        let invalid_session = CommunicationValue::new(CommunicationType::StateSubscribe)
            .with_sender(7)
            .add_typed_default(DataType::SessionId, DataValue::SignedNumber(0))
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(vec![DataValue::SignedNumber(20)]),
            );
        assert_eq!(parse_subscription(&invalid_session), Err("session_id"));
    }

    #[test]
    fn empty_subscription_is_valid_and_authoritative() {
        let parsed = parse_subscription(&request(DataValue::Array(Vec::new()))).unwrap();
        assert_eq!(parsed, (7, 11, Vec::new()));
    }
}
