use crate::{
    db::pool,
    error::{OmegaError, Result},
    models::{IotaId, UserId},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mtp::crypto::{PublicKeyBundle, sha256};
use rand::{Rng, RngExt};
use sqlx::Row;

const MAX_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
const ID_ALLOCATION_ATTEMPTS: usize = 16;
const SHORT_CODE_ATTEMPTS: usize = 32;
const SHORT_CODE_LEN: usize = 8;
const SHORT_CODE_CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ23456789";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationState {
    Pending,
    Provisioning,
    Redeemed,
    Revoked,
    Expired,
}

impl InvitationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Provisioning => "provisioning",
            Self::Redeemed => "redeemed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "provisioning" => Ok(Self::Provisioning),
            "redeemed" => Ok(Self::Redeemed),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err(OmegaError::Validation("unknown invitation state".into())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CreatedInvitation {
    pub invitation_id: i64,
    pub raw_token: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub short_url: String,
}

#[derive(Clone, Debug)]
pub struct InvitationSummary {
    pub invitation_id: i64,
    pub iota_id: i64,
    pub label: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub state: InvitationState,
    pub revision: i64,
    pub redeemed_user_id: Option<i64>,
    pub password_protected: bool,
}

#[derive(Clone, Debug)]
pub struct RedemptionResult {
    pub invitation_id: i64,
    pub user_id: UserId,
    pub iota_id: IotaId,
    pub state: InvitationState,
    pub revision: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationResult {
    pub applied: bool,
    pub state: InvitationState,
    pub revision: i64,
}

fn revocation_applies(state: InvitationState) -> bool {
    matches!(
        state,
        InvitationState::Pending | InvitationState::Provisioning
    )
}

fn hash_invitation_password_blocking(password: &str) -> Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|hash| hash.to_string())
        .map_err(|error| OmegaError::Validation(error.to_string()))
}

fn invitation_password_valid_blocking(expected: Option<&[u8]>, supplied: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(supplied) = supplied else {
        return false;
    };

    if expected.len() == 32 {
        return expected == sha256(supplied.as_bytes()).as_slice();
    }

    let Ok(expected) = str::from_utf8(expected) else {
        return false;
    };
    let Ok(expected) = PasswordHash::new(expected) else {
        return false;
    };

    Argon2::default()
        .verify_password(supplied.as_bytes(), &expected)
        .is_ok()
}

async fn hash_invitation_password(password: &str) -> Result<String> {
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || hash_invitation_password_blocking(&password))
        .await
        .map_err(|error| {
            OmegaError::Validation(format!("invitation password task failed: {error}"))
        })?
}

async fn invitation_password_valid(
    expected: Option<Vec<u8>>,
    supplied: Option<&str>,
) -> Result<bool> {
    let supplied = supplied.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        invitation_password_valid_blocking(expected.as_deref(), supplied.as_deref())
    })
    .await
    .map_err(|error| OmegaError::Validation(format!("invitation password task failed: {error}")))
}

pub async fn create(
    iota_id: IotaId,
    lifetime_seconds: i64,
    password: Option<&str>,
    label: Option<&str>,
) -> Result<CreatedInvitation> {
    if !super::user_repo::valid_protocol_id(iota_id.0)
        || !(1..=MAX_LIFETIME_SECONDS).contains(&lifetime_seconds)
        || password.is_some_and(str::is_empty)
        || label.is_some_and(|value| value.len() > 255)
    {
        return Err(OmegaError::Validation("invalid invitation options".into()));
    }
    let password_hash = match password {
        Some(password) => Some(hash_invitation_password(password).await?),
        None => None,
    };

    for _ in 0..ID_ALLOCATION_ATTEMPTS {
        let invitation_id = super::user_repo::generate_protocol_id().0;
        let mut secret = [0_u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let secret = URL_SAFE_NO_PAD.encode(secret);
        let token_hash = sha256(secret.as_bytes());

        for _ in 0..SHORT_CODE_ATTEMPTS {
            let short_code = generate_short_code();
            let short_code_hash = sha256(short_code.as_bytes());
            let mut transaction = pool().await?.begin().await?;
            let direct = sqlx::query(
                "INSERT INTO direct_link_keys (key_hash, target_kind) VALUES (?, 'invitation')",
            )
            .bind(short_code_hash.as_slice())
            .execute(&mut *transaction)
            .await;
            if let Err(error) = direct {
                if super::user_repo::is_duplicate_key(&error) {
                    continue;
                }
                return Err(error.into());
            }

            let invitation = sqlx::query(
                "INSERT INTO user_invitations \
                 (invitation_id, token_hash, short_token_hash, password_hash, iota_id, label, expires_at) \
                 VALUES (?, ?, ?, ?, ?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND))",
            )
            .bind(invitation_id)
            .bind(token_hash.as_slice())
            .bind(short_code_hash.as_slice())
            .bind(password_hash.as_deref().map(str::as_bytes))
            .bind(iota_id.0)
            .bind(label.map(str::as_bytes))
            .bind(lifetime_seconds)
            .execute(&mut *transaction)
            .await;
            if let Err(error) = invitation {
                if super::user_repo::is_duplicate_key(&error) {
                    break;
                }
                return Err(error.into());
            }

            sqlx::query(
                "INSERT INTO invitation_short_links (key_hash, invitation_id) VALUES (?, ?)",
            )
            .bind(short_code_hash.as_slice())
            .bind(invitation_id)
            .execute(&mut *transaction)
            .await?;
            let timestamps = sqlx::query(
                "SELECT CAST(UNIX_TIMESTAMP(created_at) * 1000 AS SIGNED) AS created_at_ms, \
                        CAST(UNIX_TIMESTAMP(expires_at) * 1000 AS SIGNED) AS expires_at_ms \
                 FROM user_invitations WHERE invitation_id = ?",
            )
            .bind(invitation_id)
            .fetch_one(&mut *transaction)
            .await?;
            transaction.commit().await?;

            let raw_token = format!("tinv1::o::{}::{invitation_id}::{secret}", iota_id.0);
            let public_urls = crate::config::public_urls()
                .map_err(|error| OmegaError::Validation(error.to_string()))?;
            return Ok(CreatedInvitation {
                invitation_id,
                raw_token,
                created_at_ms: timestamps.get("created_at_ms"),
                expires_at_ms: timestamps.get("expires_at_ms"),
                short_url: format!("{}/direct/{short_code}", public_urls.omega_base_url),
            });
        }
    }
    Err(OmegaError::Validation(
        "could not allocate a unique invitation".into(),
    ))
}

pub async fn list(iota_id: IotaId) -> Result<Vec<InvitationSummary>> {
    expire_pending().await?;
    let rows = sqlx::query(
        "SELECT invitation_id, iota_id, label, \
         CAST(UNIX_TIMESTAMP(created_at) * 1000 AS SIGNED) AS created_at_ms, \
         CAST(UNIX_TIMESTAMP(expires_at) * 1000 AS SIGNED) AS expires_at_ms, \
         state, revision, redeemed_user_id, password_hash IS NOT NULL AS password_protected \
         FROM user_invitations WHERE iota_id = ? ORDER BY created_at DESC",
    )
    .bind(iota_id.0)
    .fetch_all(&pool().await?)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(InvitationSummary {
                invitation_id: row.get("invitation_id"),
                iota_id: row.get("iota_id"),
                label: row
                    .get::<Option<Vec<u8>>, _>("label")
                    .map(String::from_utf8)
                    .transpose()
                    .map_err(|error| OmegaError::Validation(error.to_string()))?,
                created_at_ms: row.get("created_at_ms"),
                expires_at_ms: row.get("expires_at_ms"),
                state: InvitationState::parse(row.get::<String, _>("state").as_str())?,
                revision: row.get("revision"),
                redeemed_user_id: row.get("redeemed_user_id"),
                password_protected: row.get::<i8, _>("password_protected") != 0,
            })
        })
        .collect()
}

pub async fn revoke(invitation_id: i64, iota_id: IotaId) -> Result<RevocationResult> {
    let database = pool().await?;
    let mut transaction = database.begin().await?;
    let row = sqlx::query(
        "SELECT state, revision, redeemed_user_id FROM user_invitations \
         WHERE invitation_id = ? AND iota_id = ? FOR UPDATE",
    )
    .bind(invitation_id)
    .bind(iota_id.0)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Err(OmegaError::NotFound);
    };
    let state = InvitationState::parse(row.get::<String, _>("state").as_str())?;
    if state == InvitationState::Revoked {
        let revision: i64 = row.get("revision");
        transaction.commit().await?;
        return Ok(RevocationResult {
            applied: false,
            state,
            revision,
        });
    }
    if !revocation_applies(state) {
        let revision: i64 = row.get("revision");
        transaction.commit().await?;
        return Ok(RevocationResult {
            applied: false,
            state,
            revision,
        });
    }
    if state == InvitationState::Provisioning {
        let user_id = row
            .get::<Option<i64>, _>("redeemed_user_id")
            .ok_or_else(|| OmegaError::Validation("provisioning invitation has no user".into()))?;
        super::user_repo::queue_user_erasure_in_tx(
            &mut transaction,
            UserId::from(user_id),
            iota_id,
        )
        .await?;
        sqlx::query(
            "DELETE FROM pending_iota_user_provisioning WHERE invitation_id = ? AND iota_id = ?",
        )
        .bind(invitation_id)
        .bind(iota_id.0)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "UPDATE user_invitations SET state = 'revoked', revoked_at = UTC_TIMESTAMP(), \
         revision = revision + 1 WHERE invitation_id = ? AND iota_id = ?",
    )
    .bind(invitation_id)
    .bind(iota_id.0)
    .execute(&mut *transaction)
    .await?;
    let revision = sqlx::query_scalar::<_, i64>(
        "SELECT revision FROM user_invitations WHERE invitation_id = ?",
    )
    .bind(invitation_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(RevocationResult {
        applied: true,
        state: InvitationState::Revoked,
        revision,
    })
}

pub async fn redeem(
    invitation_id: i64,
    iota_id: IotaId,
    credential: &str,
    password: Option<&str>,
    username: &str,
    public_key: PublicKeyBundle,
    reset_token: &str,
) -> Result<RedemptionResult> {
    if !super::user_repo::valid_protocol_id(invitation_id)
        || !super::user_repo::valid_protocol_id(iota_id.0)
        || !super::user_repo::valid_username(username)
        || reset_token.is_empty()
    {
        return Err(OmegaError::Validation(
            "invalid invitation redemption".into(),
        ));
    }
    let public_key = public_key.try_as_bytes()?;
    let credential_hash = credential_hash(credential, invitation_id, iota_id)?;
    let database = pool().await?;
    let expected_password = sqlx::query_scalar::<_, Option<Vec<u8>>>(
        "SELECT password_hash FROM user_invitations WHERE invitation_id = ? AND iota_id = ?",
    )
    .bind(invitation_id)
    .bind(iota_id.0)
    .fetch_optional(&database)
    .await?
    .ok_or(OmegaError::NotFound)?;
    if !invitation_password_valid(expected_password, password).await? {
        return Err(OmegaError::Invitation("invitation_password_invalid"));
    }
    let mut transaction = database.begin().await?;
    let row = sqlx::query(
        "SELECT state, revision, expires_at > UTC_TIMESTAMP() AS current, token_hash, \
         short_token_hash, password_hash, redeemed_user_id \
         FROM user_invitations WHERE invitation_id = ? AND iota_id = ? FOR UPDATE",
    )
    .bind(invitation_id)
    .bind(iota_id.0)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(OmegaError::NotFound)?;
    let state = InvitationState::parse(row.get::<String, _>("state").as_str())?;
    let token_hash: Vec<u8> = row.get("token_hash");
    let short_hash: Option<Vec<u8>> = row.get("short_token_hash");
    if token_hash != credential_hash && short_hash.as_deref() != Some(credential_hash.as_slice()) {
        return Err(OmegaError::Invitation("invitation_invalid"));
    }
    if matches!(
        state,
        InvitationState::Provisioning | InvitationState::Redeemed
    ) {
        let user_id = UserId::from(
            row.get::<Option<i64>, _>("redeemed_user_id")
                .ok_or_else(|| OmegaError::Validation("invitation has no redeemed user".into()))?,
        );
        let account = sqlx::query(
            "SELECT username, public_key, token FROM users WHERE id = ? AND iota_id = ? LIMIT 1",
        )
        .bind(user_id.0)
        .bind(iota_id.0)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(OmegaError::NotFound)?;
        if account.get::<Vec<u8>, _>("username") != username.as_bytes()
            || account.get::<Vec<u8>, _>("public_key") != public_key
            || account.get::<Vec<u8>, _>("token") != reset_token.as_bytes()
        {
            return Err(OmegaError::Invitation("invitation_already_used"));
        }
        return Ok(RedemptionResult {
            invitation_id,
            user_id,
            iota_id,
            state,
            revision: row.get("revision"),
        });
    }
    let current: i8 = row.get("current");
    if state == InvitationState::Revoked {
        return Err(OmegaError::Invitation("invitation_revoked"));
    }
    if state == InvitationState::Expired || current == 0 {
        return Err(OmegaError::Invitation("invitation_expired"));
    }
    if state != InvitationState::Pending {
        return Err(OmegaError::Invitation("invitation_already_used"));
    }
    if sqlx::query("SELECT 1 FROM users WHERE username = ? LIMIT 1")
        .bind(username.as_bytes())
        .fetch_optional(&mut *transaction)
        .await?
        .is_some()
    {
        return Err(OmegaError::Invitation("username_taken"));
    }

    let mut user_id = None;
    for _ in 0..ID_ALLOCATION_ATTEMPTS {
        let candidate = super::user_repo::generate_protocol_id();
        if sqlx::query("SELECT 1 FROM users WHERE id = ? UNION ALL SELECT 1 FROM omega_file_signing_keys WHERE user_id=? LIMIT 1")
            .bind(candidate.0)
            .bind(candidate.0)
            .fetch_optional(&mut *transaction)
            .await?
            .is_none()
        {
            user_id = Some(candidate);
            break;
        }
    }
    let user_id = user_id
        .ok_or_else(|| OmegaError::Validation("could not allocate a unique user ID".into()))?;
    sqlx::query(
        "INSERT INTO users (id, username, public_key, iota_id, token) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id.0)
    .bind(username.as_bytes())
    .bind(&public_key)
    .bind(iota_id.0)
    .bind(reset_token.as_bytes())
    .execute(&mut *transaction)
    .await?;
    super::user_repo::archive_file_signing_key(&mut transaction, user_id, &public_key).await?;
    sqlx::query(
        "UPDATE user_invitations SET state = 'provisioning', redeemed_user_id = ?, \
         revision = revision + 1 \
         WHERE invitation_id = ?",
    )
    .bind(user_id.0)
    .bind(invitation_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO pending_iota_user_provisioning \
         (user_id, iota_id, invitation_id, username, public_key) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id.0)
    .bind(iota_id.0)
    .bind(invitation_id)
    .bind(username.as_bytes())
    .bind(&public_key)
    .execute(&mut *transaction)
    .await?;
    super::user_repo::enqueue_iota_snapshot(&mut transaction, iota_id.0).await?;
    transaction.commit().await?;
    Ok(RedemptionResult {
        invitation_id,
        user_id,
        iota_id,
        state: InvitationState::Provisioning,
        revision: row.get::<i64, _>("revision") + 1,
    })
}

pub async fn state(invitation_id: i64, iota_id: IotaId) -> Result<RedemptionResult> {
    expire_pending().await?;
    let row = sqlx::query(
        "SELECT state, revision, redeemed_user_id FROM user_invitations WHERE invitation_id = ? AND iota_id = ?",
    )
    .bind(invitation_id)
    .bind(iota_id.0)
    .fetch_optional(&pool().await?)
    .await?
    .ok_or(OmegaError::NotFound)?;
    let user_id: Option<i64> = row.get("redeemed_user_id");
    Ok(RedemptionResult {
        invitation_id,
        user_id: UserId::from(user_id.ok_or_else(|| {
            OmegaError::Validation("invitation has not entered provisioning".into())
        })?),
        iota_id,
        state: InvitationState::parse(row.get::<String, _>("state").as_str())?,
        revision: row.get("revision"),
    })
}

pub async fn acknowledge(invitation_id: i64, user_id: UserId, iota_id: IotaId) -> Result<bool> {
    let database = pool().await?;
    let mut transaction = database.begin().await?;
    let row = sqlx::query(
        "SELECT state, redeemed_user_id FROM user_invitations \
         WHERE invitation_id = ? AND iota_id = ? FOR UPDATE",
    )
    .bind(invitation_id)
    .bind(iota_id.0)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(false);
    };
    if row.get::<Option<i64>, _>("redeemed_user_id") != Some(user_id.0) {
        transaction.rollback().await?;
        return Ok(false);
    }
    let state = InvitationState::parse(row.get::<String, _>("state").as_str())?;
    if state == InvitationState::Redeemed {
        transaction.commit().await?;
        return Ok(true);
    }
    if state != InvitationState::Provisioning {
        transaction.rollback().await?;
        return Ok(false);
    }
    sqlx::query(
        "UPDATE user_invitations SET state = 'redeemed', redeemed_at = UTC_TIMESTAMP(), \
         revision = revision + 1 WHERE invitation_id = ? AND redeemed_user_id = ? AND iota_id = ?",
    )
    .bind(invitation_id)
    .bind(user_id.0)
    .bind(iota_id.0)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "DELETE FROM pending_iota_user_provisioning \
         WHERE invitation_id = ? AND user_id = ? AND iota_id = ?",
    )
    .bind(invitation_id)
    .bind(user_id.0)
    .bind(iota_id.0)
    .execute(&mut *transaction)
    .await?;
    super::user_repo::enqueue_iota_snapshot(&mut transaction, iota_id.0).await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn direct_target(short_code: &str) -> Result<Option<String>> {
    let normalized = normalize_short_code(short_code);
    let key_hash = sha256(normalized.as_bytes());
    let row = sqlx::query(
        "SELECT i.invitation_id, i.iota_id FROM direct_link_keys d \
         JOIN invitation_short_links l ON l.key_hash = d.key_hash \
         JOIN user_invitations i ON i.invitation_id = l.invitation_id \
         WHERE d.key_hash = ? AND d.target_kind = 'invitation' \
         AND i.state IN ('pending', 'provisioning') \
         AND i.expires_at > UTC_TIMESTAMP()",
    )
    .bind(key_hash.as_slice())
    .fetch_optional(&pool().await?)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let invitation_id: i64 = row.get("invitation_id");
    let iota_id: i64 = row.get("iota_id");
    let base_url = crate::config::public_urls()
        .map_err(|error| OmegaError::Validation(error.to_string()))?
        .client_base_url;
    Ok(Some(format!(
        "{base_url}/register#invitation={normalized}&invitation_id={invitation_id}&iota_id={iota_id}"
    )))
}

async fn expire_pending() -> Result<()> {
    sqlx::query(
        "UPDATE user_invitations SET state = 'expired', revision = revision + 1 \
         WHERE state = 'pending' AND expires_at <= UTC_TIMESTAMP()",
    )
    .execute(&pool().await?)
    .await?;
    Ok(())
}

fn credential_hash(credential: &str, invitation_id: i64, iota_id: IotaId) -> Result<Vec<u8>> {
    if credential.starts_with("tinv1::") {
        let (_, parsed_iota, parsed_invitation, secret) = parse_token(credential)?;
        if parsed_iota != iota_id.0 || parsed_invitation != invitation_id {
            return Err(OmegaError::Validation(
                "invitation token target mismatch".into(),
            ));
        }
        Ok(sha256(secret.as_bytes()).to_vec())
    } else {
        Ok(sha256(normalize_short_code(credential).as_bytes()).to_vec())
    }
}

fn parse_token(token: &str) -> Result<(&str, i64, i64, &str)> {
    let parts: Vec<_> = token.split("::").collect();
    if parts.len() != 5 || parts[0] != "tinv1" || parts[1] != "o" || parts[4].is_empty() {
        return Err(OmegaError::Validation("malformed invitation token".into()));
    }
    let iota_id = parts[2]
        .parse::<i64>()
        .map_err(|_| OmegaError::Validation("malformed invitation token".into()))?;
    let invitation_id = parts[3]
        .parse::<i64>()
        .map_err(|_| OmegaError::Validation("malformed invitation token".into()))?;
    Ok((parts[1], iota_id, invitation_id, parts[4]))
}

fn generate_short_code() -> String {
    let mut rng = rand::rng();
    (0..SHORT_CODE_LEN)
        .map(|_| {
            let index = rng.random_range(0..SHORT_CODE_CHARS.len());
            SHORT_CODE_CHARS[index] as char
        })
        .collect()
}

fn normalize_short_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character != '-')
        .map(|character| match character {
            'Q' | 'O' => '0',
            'I' => 'l',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        InvitationState, SHORT_CODE_CHARS, SHORT_CODE_LEN, generate_short_code,
        invitation_password_valid_blocking, normalize_short_code, parse_token, revocation_applies,
        sha256,
    };

    #[test]
    fn parses_versioned_omega_token() {
        let (_, iota_id, invitation_id, secret) = parse_token("tinv1::o::42::73::secret").unwrap();
        assert_eq!((iota_id, invitation_id, secret), (42, 73, "secret"));
    }

    #[test]
    fn rejects_wrong_token_authority() {
        assert!(parse_token("tinv1::i::42::73::secret").is_err());
    }

    #[test]
    fn normalizes_human_friendly_short_codes() {
        assert_eq!(normalize_short_code("QOI-Iabc"), "00llabc");
    }

    #[test]
    fn terminal_invitation_states_reconcile_without_applying_revocation() {
        assert!(!revocation_applies(InvitationState::Redeemed));
        assert!(!revocation_applies(InvitationState::Expired));
        assert!(!revocation_applies(InvitationState::Revoked));
        assert!(revocation_applies(InvitationState::Pending));
        assert!(revocation_applies(InvitationState::Provisioning));
    }

    #[test]
    fn generated_short_codes_use_the_invitation_alphabet() {
        for _ in 0..64 {
            let code = generate_short_code();
            assert_eq!(code.len(), SHORT_CODE_LEN);
            assert!(code.bytes().all(|byte| SHORT_CODE_CHARS.contains(&byte)));
        }
    }

    #[test]
    fn optional_invitation_password_only_constrains_protected_invitations() {
        let expected = sha256(b"correct");
        assert!(invitation_password_valid_blocking(None, None));
        assert!(invitation_password_valid_blocking(None, Some("wrong")));
        assert!(!invitation_password_valid_blocking(Some(&expected), None));
        assert!(!invitation_password_valid_blocking(
            Some(&expected),
            Some("wrong")
        ));
        assert!(invitation_password_valid_blocking(
            Some(&expected),
            Some("correct")
        ));
    }
}
