use crate::{
    db::{DbPool, pool},
    error::{OmegaError, Result},
    models::{IotaId, User, UserId},
    sql::connection_status::UserStatus,
};
use mtp::crypto::PublicKeyBundle;
use sqlx::{FromRow, MySql, QueryBuilder, Row, Transaction};
use std::collections::HashMap;

pub const MAX_PROTOCOL_ID: i64 = (1_i64 << 48) - 1;
const ID_ALLOCATION_ATTEMPTS: usize = 16;
const ENQUEUE_IOTA_SNAPSHOT_QUERY: &str = "INSERT INTO iota_snapshot_outbox (iota_id, revision, updated_at) \
     VALUES (?, 1, UTC_TIMESTAMP()) \
     ON DUPLICATE KEY UPDATE revision = revision + 1, updated_at = VALUES(updated_at)";
const COMPLETE_IOTA_SNAPSHOT_QUERY: &str =
    "DELETE FROM iota_snapshot_outbox WHERE iota_id = ? AND revision = ?";

#[derive(Clone, Debug)]
pub struct PendingIotaUserProvisioning {
    pub user_id: UserId,
    pub invitation_id: i64,
    pub username: String,
    pub public_key: PublicKeyBundle,
    pub invitation_revision: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingIotaSnapshot {
    pub iota_id: IotaId,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorPublicationState {
    pub revision: i64,
    pub issued_at: i64,
    pub valid_until: Option<i64>,
}

fn next_descriptor_publication(
    current_hash: &[u8],
    source_hash: &[u8],
    current: DescriptorPublicationState,
    valid_until: Option<i64>,
    now: i64,
) -> Result<DescriptorPublicationState> {
    if current_hash == source_hash {
        return Ok(current);
    }
    Ok(DescriptorPublicationState {
        revision: current
            .revision
            .checked_add(1)
            .ok_or_else(|| OmegaError::Validation("descriptor revision is exhausted".into()))?,
        issued_at: now,
        valid_until,
    })
}

#[derive(Debug, Default)]
pub struct UserPatch {
    pub username: Option<String>,
    pub display: Option<String>,
    pub avatar: Option<Vec<u8>>,
    pub about: Option<String>,
    pub status: Option<String>,
    pub public_key: Option<PublicKeyBundle>,
    pub presence_preference: Option<UserStatus>,
}

impl UserPatch {
    pub fn is_empty(&self) -> bool {
        self.username.is_none()
            && self.display.is_none()
            && self.avatar.is_none()
            && self.about.is_none()
            && self.status.is_none()
            && self.public_key.is_none()
            && self.presence_preference.is_none()
    }
}

pub async fn pending_iota_user_provisioning(
    iota_id: IotaId,
) -> Result<Vec<PendingIotaUserProvisioning>> {
    let rows = sqlx::query(
        "SELECT p.user_id, p.iota_id, p.invitation_id, p.username, p.public_key, \
                i.revision AS invitation_revision \
         FROM pending_iota_user_provisioning p \
         JOIN user_invitations i ON i.invitation_id = p.invitation_id \
         WHERE p.iota_id = ? ORDER BY p.created_at",
    )
    .bind(iota_id.0)
    .fetch_all(&pool().await?)
    .await?;
    rows.into_iter()
        .map(|row| {
            let public_key = PublicKeyBundle::from_bytes(&row.get::<Vec<u8>, _>("public_key"))
                .map_err(|error| OmegaError::Validation(error.to_string()))?;
            Ok(PendingIotaUserProvisioning {
                user_id: UserId::from(row.get::<i64, _>("user_id")),
                invitation_id: row.get("invitation_id"),
                username: String::from_utf8(row.get::<Vec<u8>, _>("username"))
                    .map_err(|error| OmegaError::Validation(error.to_string()))?,
                public_key,
                invitation_revision: row.get("invitation_revision"),
            })
        })
        .collect()
}

pub async fn pending_provisioning_iota_ids() -> Result<Vec<IotaId>> {
    let rows =
        sqlx::query_scalar::<_, i64>("SELECT DISTINCT iota_id FROM pending_iota_user_provisioning")
            .fetch_all(&pool().await?)
            .await?;
    Ok(rows.into_iter().map(IotaId::from).collect())
}

pub fn generate_protocol_id() -> UserId {
    loop {
        let value = rand::random::<u64>() & ((1_u64 << 48) - 1);
        if value != 0 {
            return UserId::from(value as i64);
        }
    }
}

pub fn valid_protocol_id(id: i64) -> bool {
    (1..=MAX_PROTOCOL_ID).contains(&id)
}

/// Allocate an ID that is durable, short-lived, and bound to the connected
/// Iota.  `token` is presented again when completing the registration.
pub async fn allocate_registration(
    iota_id: IotaId,
    request_token: Option<uuid::Uuid>,
    request_id: u32,
) -> Result<(UserId, String)> {
    allocate_registration_with_pool(&pool().await?, iota_id, request_token, request_id).await
}

async fn allocate_registration_with_pool(
    database: &DbPool,
    iota_id: IotaId,
    request_token: Option<uuid::Uuid>,
    request_id: u32,
) -> Result<(UserId, String)> {
    if !valid_protocol_id(iota_id.0) {
        return Err(OmegaError::Validation(
            "Iota ID is outside the 48-bit protocol range".into(),
        ));
    }

    sqlx::query(
        "UPDATE registration_leases SET request_id = NULL, request_token = NULL \
         WHERE (request_id IS NOT NULL OR request_token IS NOT NULL) \
         AND expires_at < UTC_TIMESTAMP()",
    )
    .execute(database)
    .await?;
    let request_token = request_token.map(|token| token.as_bytes().to_vec());
    let legacy_request_id = request_token.is_none().then_some(request_id);

    for _ in 0..ID_ALLOCATION_ATTEMPTS {
        let id = generate_protocol_id();
        let user_exists = sqlx::query("SELECT 1 FROM users WHERE id = ? LIMIT 1")
            .bind(id.0)
            .fetch_optional(database)
            .await?
            .is_some();
        if user_exists {
            continue;
        }
        let token = uuid::Uuid::new_v4().to_string();
        let result = sqlx::query(
            "INSERT INTO registration_leases \
             (token, user_id, iota_id, request_id, request_token, expires_at) \
             VALUES (?, ?, ?, ?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 10 MINUTE))",
        )
        .bind(&token)
        .bind(id.0)
        .bind(iota_id.0)
        .bind(legacy_request_id)
        .bind(request_token.as_deref())
        .execute(database)
        .await;
        match result {
            Ok(_) => return Ok((id, token)),
            Err(error) if is_duplicate_key(&error) => {
                let existing = if let Some(request_token) = request_token.as_deref() {
                    sqlx::query(
                        "SELECT user_id, token, expires_at >= UTC_TIMESTAMP() AS current \
                         FROM registration_leases WHERE iota_id = ? AND request_token = ?",
                    )
                    .bind(iota_id.0)
                    .bind(request_token)
                    .fetch_optional(database)
                    .await?
                } else {
                    sqlx::query(
                        "SELECT user_id, token, expires_at >= UTC_TIMESTAMP() AS current \
                         FROM registration_leases WHERE iota_id = ? AND request_id = ?",
                    )
                    .bind(iota_id.0)
                    .bind(request_id)
                    .fetch_optional(database)
                    .await?
                };
                if let Some(existing) = existing {
                    let current: i8 = existing.get("current");
                    if current != 0 {
                        return Ok((
                            UserId::from(existing.get::<i64, _>("user_id")),
                            existing.get::<String, _>("token"),
                        ));
                    }
                }
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(OmegaError::Validation(
        "could not allocate a unique registration ID".into(),
    ))
}

pub(crate) fn is_duplicate_key(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

const USER_BY_USERNAME_QUERY: &str = "SELECT id, iota_id, username, display, status, presence_preference, about, avatar, sub_level, sub_end, public_key, token, CAST(UNIX_TIMESTAMP(created_at) * 1000 AS SIGNED) AS created_at FROM users WHERE username = ?";
const USER_BY_ID_QUERY: &str = "SELECT id, iota_id, username, display, status, presence_preference, about, avatar, sub_level, sub_end, public_key, token, CAST(UNIX_TIMESTAMP(created_at) * 1000 AS SIGNED) AS created_at FROM users WHERE id = ?";
const USER_COLUMNS: &str = "SELECT id, iota_id, username, display, status, presence_preference, about, avatar, sub_level, sub_end, public_key, token, CAST(UNIX_TIMESTAMP(created_at) * 1000 AS SIGNED) AS created_at FROM users";

#[derive(FromRow)]
struct UserRow {
    id: i64,
    iota_id: Option<i64>,
    username: Vec<u8>,
    display: Option<Vec<u8>>,
    status: Option<Vec<u8>>,
    presence_preference: Vec<u8>,
    about: Option<Vec<u8>>,
    avatar: Option<Vec<u8>>,
    sub_level: i32,
    sub_end: i64,
    public_key: Vec<u8>,
    token: Vec<u8>,
    created_at: i64,
}

impl TryFrom<UserRow> for User {
    type Error = sqlx::Error;

    fn try_from(row: UserRow) -> std::result::Result<Self, Self::Error> {
        let public_key = PublicKeyBundle::from_bytes(&row.public_key)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
        let decode =
            |value| String::from_utf8(value).map_err(|error| sqlx::Error::Decode(Box::new(error)));
        Ok(User {
            id: row.id.into(),
            iota_id: row.iota_id.map(IotaId::from),
            username: decode(row.username)?,
            display: row.display.map(decode).transpose()?,
            status: row.status.map(decode).transpose()?,
            presence_preference: decode(row.presence_preference)?,
            about: row.about.map(decode).transpose()?,
            avatar: row.avatar,
            sub_level: row.sub_level,
            sub_end: row.sub_end,
            public_key,
            token: decode(row.token)?,
            created_at: row.created_at,
        })
    }
}

pub async fn get_by_username(username: &str) -> Result<User> {
    let row = sqlx::query_as::<_, UserRow>(USER_BY_USERNAME_QUERY)
        .bind(username)
        .fetch_optional(&pool().await?)
        .await?
        .ok_or(OmegaError::NotFound)?;
    row.try_into().map_err(OmegaError::from)
}

pub async fn get_by_user_id(id: UserId) -> Result<User> {
    let row = sqlx::query_as::<_, UserRow>(USER_BY_ID_QUERY)
        .bind(id.0)
        .fetch_optional(&pool().await?)
        .await?
        .ok_or(OmegaError::NotFound)?;
    row.try_into().map_err(OmegaError::from)
}

pub async fn descriptor_publication_state(
    user: UserId,
    source: &[u8],
    valid_until: Option<i64>,
    now: i64,
) -> Result<DescriptorPublicationState> {
    let source_hash = mtp::crypto::sha256(source);
    let mut transaction = pool().await?.begin().await?;
    sqlx::query(
        "INSERT INTO omega_principal_descriptors \
         (user_id, source_hash, revision, issued_at, valid_until) VALUES (?, ?, 0, ?, ?) \
         ON DUPLICATE KEY UPDATE user_id = VALUES(user_id)",
    )
    .bind(user.0)
    .bind(source_hash.as_slice())
    .bind(now)
    .bind(valid_until)
    .execute(&mut *transaction)
    .await?;
    let row = sqlx::query(
        "SELECT source_hash, revision, issued_at, valid_until \
         FROM omega_principal_descriptors WHERE user_id = ? FOR UPDATE",
    )
    .bind(user.0)
    .fetch_one(&mut *transaction)
    .await?;
    let current_hash: Vec<u8> = row.get("source_hash");
    let mut state = DescriptorPublicationState {
        revision: row.get("revision"),
        issued_at: row.get("issued_at"),
        valid_until: row.get("valid_until"),
    };
    let next = next_descriptor_publication(&current_hash, &source_hash, state, valid_until, now)?;
    if next != state {
        state = next;
        sqlx::query(
            "UPDATE omega_principal_descriptors SET source_hash = ?, revision = ?, \
             issued_at = ?, valid_until = ? WHERE user_id = ?",
        )
        .bind(source_hash.as_slice())
        .bind(state.revision)
        .bind(state.issued_at)
        .bind(state.valid_until)
        .bind(user.0)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(state)
}

pub async fn get_users_by_iota_id(id: IotaId) -> Result<Vec<User>> {
    get_users_by_iota_ids(&[id.0]).await
}

fn normalized_ids(ids: &[i64]) -> Vec<i64> {
    let mut ids = ids
        .iter()
        .copied()
        .filter(|id| valid_protocol_id(*id))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn append_in_clause(query: &mut QueryBuilder<MySql>, ids: &[i64]) {
    query.push("(");
    for (index, id) in ids.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push_bind(*id);
    }
    query.push(")");
}

async fn fetch_users(mut query: QueryBuilder<MySql>) -> Result<Vec<User>> {
    query
        .build_query_as::<UserRow>()
        .fetch_all(&pool().await?)
        .await?
        .into_iter()
        .map(|row| row.try_into().map_err(OmegaError::from))
        .collect()
}

pub async fn get_users_by_ids(ids: &[i64]) -> Result<Vec<User>> {
    let ids = normalized_ids(ids);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut query = QueryBuilder::<MySql>::new(USER_COLUMNS);
    query.push(" WHERE id IN ");
    append_in_clause(&mut query, &ids);
    fetch_users(query).await
}

pub async fn get_users_by_iota_ids(ids: &[i64]) -> Result<Vec<User>> {
    let ids = normalized_ids(ids);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut query = QueryBuilder::<MySql>::new(USER_COLUMNS);
    query.push(" WHERE iota_id IN ");
    append_in_clause(&mut query, &ids);
    fetch_users(query).await
}

pub async fn get_users_by_ids_and_iota_ids(
    user_ids: &[i64],
    iota_ids: &[i64],
) -> Result<Vec<User>> {
    let user_ids = normalized_ids(user_ids);
    let iota_ids = normalized_ids(iota_ids);
    if user_ids.is_empty() && iota_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut query = QueryBuilder::<MySql>::new(USER_COLUMNS);
    query.push(" WHERE ");
    if !user_ids.is_empty() {
        query.push("id IN ");
        append_in_clause(&mut query, &user_ids);
    }
    if !iota_ids.is_empty() {
        if !user_ids.is_empty() {
            query.push(" OR ");
        }
        query.push("iota_id IN ");
        append_in_clause(&mut query, &iota_ids);
    }
    fetch_users(query).await
}

#[derive(FromRow)]
struct PresencePreferenceRow {
    id: i64,
    presence_preference: Vec<u8>,
}

pub async fn get_presence_preferences(ids: &[i64]) -> Result<HashMap<i64, UserStatus>> {
    get_presence_preferences_with_pool(&pool().await?, ids).await
}

async fn get_presence_preferences_with_pool(
    database: &DbPool,
    ids: &[i64],
) -> Result<HashMap<i64, UserStatus>> {
    let ids = normalized_ids(ids);
    if ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut query =
        QueryBuilder::<MySql>::new("SELECT id, presence_preference FROM users WHERE id IN ");
    append_in_clause(&mut query, &ids);
    let rows = query
        .build_query_as::<PresencePreferenceRow>()
        .fetch_all(database)
        .await?;
    let mut preferences = HashMap::with_capacity(rows.len());
    for row in rows {
        let status = String::from_utf8(row.presence_preference)
            .ok()
            .and_then(|value| UserStatus::from_client_preference(&value));
        let status = match status {
            Some(status) => status,
            None => {
                crate::log_in!(
                    crate::util::logger::PrintType::General,
                    "Invalid persisted presence preference for user {}, using user_online",
                    row.id
                );
                UserStatus::user_online
            }
        };
        preferences.insert(row.id, status);
    }
    Ok(preferences)
}

pub async fn update_user_patch(id: UserId, patch: &UserPatch) -> Result<()> {
    update_user_patch_with_pool(&pool().await?, id, patch).await
}

async fn update_user_patch_with_pool(
    database: &DbPool,
    id: UserId,
    patch: &UserPatch,
) -> Result<()> {
    if patch.is_empty() {
        return Ok(());
    }

    let public_key = patch
        .public_key
        .as_ref()
        .map(PublicKeyBundle::try_as_bytes)
        .transpose()?;
    let mut transaction = database.begin().await?;
    let mut query = QueryBuilder::<MySql>::new("UPDATE users SET ");
    {
        let mut fields = query.separated(", ");
        if let Some(value) = &patch.username {
            fields
                .push("username = ")
                .push_bind_unseparated(value.as_bytes());
        }
        if let Some(value) = &patch.display {
            fields
                .push("display = ")
                .push_bind_unseparated(value.as_bytes());
        }
        if let Some(value) = &patch.avatar {
            fields.push("avatar = ").push_bind_unseparated(value);
        }
        if let Some(value) = &patch.about {
            fields
                .push("about = ")
                .push_bind_unseparated(value.as_bytes());
        }
        if let Some(value) = &patch.status {
            fields
                .push("status = ")
                .push_bind_unseparated(value.as_bytes());
        }
        if let Some(value) = &public_key {
            fields.push("public_key = ").push_bind_unseparated(value);
        }
        if let Some(value) = &patch.presence_preference {
            fields
                .push("presence_preference = ")
                .push_bind_unseparated(value.to_string().into_bytes());
        }
    }
    query.push(" WHERE id = ").push_bind(id.0);
    let result = query.build().execute(&mut *transaction).await?;
    if result.rows_affected() == 0
        && sqlx::query_scalar::<_, i32>("SELECT 1 FROM users WHERE id = ?")
            .bind(id.0)
            .fetch_optional(&mut *transaction)
            .await?
            .is_none()
    {
        return Err(OmegaError::NotFound);
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn change_iota_id(id: UserId, value: Option<IotaId>) -> Result<()> {
    let mut transaction = pool().await?.begin().await?;
    let previous = sqlx::query("SELECT iota_id FROM users WHERE id = ? FOR UPDATE")
        .bind(id.0)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(OmegaError::NotFound)?;
    let previous_iota_id: Option<i64> = previous.get("iota_id");
    sqlx::query("UPDATE users SET iota_id = ? WHERE id = ?")
        .bind(value.map(|id| id.0))
        .bind(id.0)
        .execute(&mut *transaction)
        .await?;
    if let Some(iota_id) = previous_iota_id {
        enqueue_iota_snapshot(&mut transaction, iota_id).await?;
    }
    if let Some(iota_id) = value {
        enqueue_iota_snapshot(&mut transaction, iota_id.0).await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn enqueue_iota_snapshot(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    iota_id: i64,
) -> Result<()> {
    sqlx::query(ENQUEUE_IOTA_SNAPSHOT_QUERY)
        .bind(iota_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub async fn pending_iota_snapshots() -> Result<Vec<PendingIotaSnapshot>> {
    let rows =
        sqlx::query("SELECT iota_id, revision FROM iota_snapshot_outbox ORDER BY updated_at")
            .fetch_all(&pool().await?)
            .await?;
    Ok(rows
        .into_iter()
        .map(|row| PendingIotaSnapshot {
            iota_id: IotaId::from(row.get::<i64, _>("iota_id")),
            revision: row.get("revision"),
        })
        .collect())
}

pub async fn complete_iota_snapshot(snapshot: &PendingIotaSnapshot) -> Result<bool> {
    let result = sqlx::query(COMPLETE_IOTA_SNAPSHOT_QUERY)
        .bind(snapshot.iota_id.0)
        .bind(snapshot.revision)
        .execute(&pool().await?)
        .await?;
    Ok(result.rows_affected() == 1)
}
/// Delete the central identity while retaining a durable instruction for the
/// last hosting Iota. The pending row is intentionally independent of users:
/// it must outlive the account row.
pub async fn delete_user_with_pending_erasure(id: UserId) -> Result<Option<IotaId>> {
    let mut tx = pool().await?.begin().await?;
    let row = sqlx::query("SELECT iota_id FROM users WHERE id = ? FOR UPDATE")
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(OmegaError::NotFound)?;
    let iota_id: Option<i64> = row.get("iota_id");
    if let Some(iota_id) = iota_id {
        queue_user_erasure_in_tx(&mut tx, id, IotaId::from(iota_id)).await?;
    } else {
        sqlx::query("DELETE FROM registration_leases WHERE user_id = ?")
            .bind(id.0)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.0)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(iota_id.map(IotaId::from))
}

pub(crate) async fn queue_user_erasure_in_tx(
    tx: &mut Transaction<'_, MySql>,
    user_id: UserId,
    iota_id: IotaId,
) -> Result<()> {
    sqlx::query("INSERT IGNORE INTO pending_iota_user_erasure (user_id, iota_id) VALUES (?, ?)")
        .bind(user_id.0)
        .bind(iota_id.0)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM registration_leases WHERE user_id = ?")
        .bind(user_id.0)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id.0)
        .execute(&mut **tx)
        .await?;
    enqueue_iota_snapshot(tx, iota_id.0).await?;
    Ok(())
}

pub async fn pending_erasures_for_iota(iota_id: IotaId) -> Result<Vec<UserId>> {
    let rows = sqlx::query("SELECT user_id FROM pending_iota_user_erasure WHERE iota_id = ?")
        .bind(iota_id.0)
        .fetch_all(&pool().await?)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| UserId::from(row.get::<i64, _>("user_id")))
        .collect())
}

pub async fn pending_erasure_iota_ids() -> Result<Vec<IotaId>> {
    let rows = sqlx::query("SELECT DISTINCT iota_id FROM pending_iota_user_erasure")
        .fetch_all(&pool().await?)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| IotaId::from(row.get::<i64, _>("iota_id")))
        .collect())
}

pub async fn acknowledge_pending_erasure(user_id: UserId, iota_id: IotaId) -> Result<bool> {
    let result =
        sqlx::query("DELETE FROM pending_iota_user_erasure WHERE user_id = ? AND iota_id = ?")
            .bind(user_id.0)
            .bind(iota_id.0)
            .execute(&pool().await?)
            .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn register_complete_user(
    id: UserId,
    username: String,
    public_key: PublicKeyBundle,
    iota_id: IotaId,
    token: String,
    registration_token: String,
) -> Result<()> {
    if !valid_protocol_id(id.0) || !valid_protocol_id(iota_id.0) {
        return Err(OmegaError::Validation(
            "user or Iota ID is outside the 48-bit protocol range".into(),
        ));
    }
    if !valid_username(&username) {
        return Err(OmegaError::Validation("invalid username".into()));
    }
    let public_key_bytes = public_key.try_as_bytes()?;

    let mut transaction = pool().await?.begin().await?;
    let lease = sqlx::query(
        "SELECT iota_id, completed_at IS NOT NULL AS completed, \
         expires_at >= UTC_TIMESTAMP() AS current FROM registration_leases \
         WHERE token = ? AND user_id = ? FOR UPDATE",
    )
    .bind(&registration_token)
    .bind(id.0)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| OmegaError::Validation("unknown registration lease".into()))?;
    let lease_iota_id: i64 = lease.get("iota_id");
    let completed: i8 = lease.get("completed");
    let current: i8 = lease.get("current");
    if lease_iota_id != iota_id.0 || (completed == 0 && current == 0) {
        return Err(OmegaError::Validation(
            "expired or mismatched registration lease".into(),
        ));
    }

    let insert_result = sqlx::query(
        "INSERT INTO users (id, username, public_key, iota_id, token) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id.0)
    .bind(username.as_bytes())
    .bind(&public_key_bytes)
    .bind(iota_id.0)
    .bind(token.as_bytes())
    .execute(&mut *transaction)
    .await;

    let result: Result<()> = match insert_result {
        Ok(_) => Ok(()),
        Err(insert_error) => {
            let existing = sqlx::query_as::<_, UserRow>(USER_BY_ID_QUERY)
                .bind(id.0)
                .fetch_optional(&mut *transaction)
                .await?;
            let existing_matches = match existing {
                Some(existing) => {
                    let existing = User::try_from(existing).map_err(OmegaError::from)?;
                    existing.iota_id == Some(iota_id)
                        && existing.username == username
                        && existing.public_key.try_as_bytes()? == public_key_bytes
                        && existing.token == token
                }
                None => false,
            };
            if existing_matches {
                Ok(())
            } else {
                Err(insert_error.into())
            }
        }
    };
    result?;
    enqueue_iota_snapshot(&mut transaction, iota_id.0).await?;
    sqlx::query("UPDATE registration_leases SET completed_at = UTC_TIMESTAMP() WHERE token = ?")
        .bind(&registration_token)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 15
        && username
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{
        COMPLETE_IOTA_SNAPSHOT_QUERY, DescriptorPublicationState, ENQUEUE_IOTA_SNAPSHOT_QUERY,
        MAX_PROTOCOL_ID, UserPatch, allocate_registration_with_pool, generate_protocol_id,
        get_presence_preferences_with_pool, next_descriptor_publication,
        update_user_patch_with_pool, valid_protocol_id,
    };
    use crate::{
        models::{IotaId, UserId},
        sql::connection_status::UserStatus,
    };
    use sqlx::{Row, mysql::MySqlPoolOptions};

    async fn test_pool() -> Result<sqlx::MySqlPool, Box<dyn std::error::Error>> {
        Ok(MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("TEST_DB_URL")?)
            .await?)
    }

    async fn create_temp_users(
        database: &sqlx::MySqlPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(
            "CREATE TEMPORARY TABLE users (\
             id BIGINT NOT NULL PRIMARY KEY, \
             username VARBINARY(15) NOT NULL UNIQUE, \
             display VARBINARY(64) NULL, \
             avatar BLOB NULL, \
             about VARBINARY(255) NULL, \
             status VARBINARY(64) NULL, \
             public_key BLOB NULL, \
             presence_preference VARBINARY(32) NOT NULL)",
        )
        .execute(database)
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn generated_registration_ids_fit_the_mtp_wire_range() {
        for _ in 0..128 {
            assert!(valid_protocol_id(generate_protocol_id().0));
        }
        assert!(!valid_protocol_id(0));
        assert!(valid_protocol_id(MAX_PROTOCOL_ID));
        assert!(!valid_protocol_id(MAX_PROTOCOL_ID + 1));
    }

    #[test]
    fn descriptor_publication_changes_only_when_signed_fields_change() {
        let current = DescriptorPublicationState {
            revision: 4,
            issued_at: 10,
            valid_until: Some(100),
        };
        assert_eq!(
            next_descriptor_publication(b"same", b"same", current, Some(200), 20).unwrap(),
            current
        );
        assert_eq!(
            next_descriptor_publication(b"old", b"new", current, Some(200), 20).unwrap(),
            DescriptorPublicationState {
                revision: 5,
                issued_at: 20,
                valid_until: Some(200),
            }
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DB_URL pointing to a disposable MySQL database"]
    async fn older_snapshot_completion_does_not_delete_new_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = test_pool().await?;
        let mut connection = database.acquire().await?;
        sqlx::query(
            "CREATE TEMPORARY TABLE iota_snapshot_outbox (\
             iota_id BIGINT NOT NULL PRIMARY KEY, \
             revision BIGINT UNSIGNED NOT NULL DEFAULT 1, \
             updated_at DATETIME NOT NULL)",
        )
        .execute(&mut *connection)
        .await?;
        sqlx::query(ENQUEUE_IOTA_SNAPSHOT_QUERY)
            .bind(7_i64)
            .execute(&mut *connection)
            .await?;
        let pending_revision =
            sqlx::query("SELECT revision FROM iota_snapshot_outbox WHERE iota_id = ?")
                .bind(7_i64)
                .fetch_one(&mut *connection)
                .await?
                .get::<u64, _>("revision");

        sqlx::query(ENQUEUE_IOTA_SNAPSHOT_QUERY)
            .bind(7_i64)
            .execute(&mut *connection)
            .await?;
        let completion = sqlx::query(COMPLETE_IOTA_SNAPSHOT_QUERY)
            .bind(7_i64)
            .bind(pending_revision)
            .execute(&mut *connection)
            .await?;
        let current_revision =
            sqlx::query("SELECT revision FROM iota_snapshot_outbox WHERE iota_id = ?")
                .bind(7_i64)
                .fetch_one(&mut *connection)
                .await?
                .get::<u64, _>("revision");

        assert_eq!(completion.rows_affected(), 0);
        assert_eq!(current_revision, pending_revision + 1);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DB_URL pointing to a disposable MySQL database"]
    async fn registration_token_is_idempotent_across_transport_ids()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = test_pool().await?;
        create_temp_users(&database).await?;
        sqlx::query(
            "CREATE TEMPORARY TABLE registration_leases (\
             token VARCHAR(255) NOT NULL PRIMARY KEY, \
             user_id BIGINT NOT NULL, \
             iota_id BIGINT NOT NULL, \
             request_id INT UNSIGNED NULL, \
             request_token BINARY(16) NULL, \
             expires_at DATETIME NOT NULL, \
             UNIQUE KEY uk_iota_request (iota_id, request_id), \
             UNIQUE KEY uk_iota_token (iota_id, request_token))",
        )
        .execute(&database)
        .await?;
        let request_token = uuid::Uuid::new_v4();

        let first =
            allocate_registration_with_pool(&database, IotaId::from(7), Some(request_token), 1001)
                .await?;
        let second =
            allocate_registration_with_pool(&database, IotaId::from(7), Some(request_token), 1002)
                .await?;

        assert_eq!(first, second);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DB_URL pointing to a disposable MySQL database"]
    async fn failed_profile_patch_rolls_back_and_presence_preference_reloads()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = test_pool().await?;
        create_temp_users(&database).await?;
        sqlx::query(
            "INSERT INTO users (id, username, display, presence_preference) VALUES \
             (7, 'first', 'Before', 'user_online'), \
             (8, 'taken', 'Other', 'user_online')",
        )
        .execute(&database)
        .await?;
        let failed_patch = UserPatch {
            username: Some("taken".into()),
            display: Some("After".into()),
            presence_preference: Some(UserStatus::user_invisible),
            ..UserPatch::default()
        };

        assert!(
            update_user_patch_with_pool(&database, UserId::from(7), &failed_patch)
                .await
                .is_err()
        );
        let unchanged = sqlx::query("SELECT display, presence_preference FROM users WHERE id = 7")
            .fetch_one(&database)
            .await?;
        assert_eq!(unchanged.get::<Vec<u8>, _>("display"), b"Before");
        assert_eq!(
            unchanged.get::<Vec<u8>, _>("presence_preference"),
            b"user_online"
        );

        update_user_patch_with_pool(
            &database,
            UserId::from(7),
            &UserPatch {
                presence_preference: Some(UserStatus::user_invisible),
                ..UserPatch::default()
            },
        )
        .await?;
        assert_eq!(
            get_presence_preferences_with_pool(&database, &[7])
                .await?
                .get(&7),
            Some(&UserStatus::user_invisible)
        );
        Ok(())
    }
}
