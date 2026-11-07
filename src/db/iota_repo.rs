use crate::{
    db::pool,
    error::{OmegaError, Result},
    models::{Iota, IotaId},
};
use mtp::crypto::PublicKeyBundle;
use sqlx::Row;

struct IotaIdentity {
    id: IotaId,
    public_key_bytes: Vec<u8>,
}

fn public_key_identity(public_key: &PublicKeyBundle) -> Result<(Vec<u8>, [u8; 32])> {
    let bytes = public_key.try_as_bytes()?;
    let hash = mtp::crypto::sha256(&bytes);
    Ok((bytes, hash))
}

async fn get_iota_by_public_key_hash(
    database: &mut sqlx::MySqlConnection,
    public_key_hash: &[u8; 32],
) -> Result<Option<IotaIdentity>> {
    let row = sqlx::query("SELECT id, public_key FROM iotas WHERE public_key_hash = ? FOR UPDATE")
        .bind(public_key_hash.as_slice())
        .fetch_optional(&mut *database)
        .await?;
    Ok(row.map(|row| IotaIdentity {
        id: row.get::<i64, _>("id").into(),
        public_key_bytes: row.get("public_key"),
    }))
}

async fn lock_key_authority(
    database: &mut sqlx::MySqlConnection,
    public_key_hash: &[u8; 32],
) -> Result<()> {
    sqlx::query(
        "INSERT INTO iota_key_authority (public_key_hash) VALUES (?) \
         ON DUPLICATE KEY UPDATE public_key_hash = public_key_hash",
    )
    .bind(public_key_hash.as_slice())
    .execute(database)
    .await?;
    Ok(())
}

async fn is_revoked(
    database: &mut sqlx::MySqlConnection,
    public_key_hash: &[u8; 32],
) -> Result<bool> {
    Ok(sqlx::query(
        "SELECT 1 FROM iota_key_authority \
         WHERE public_key_hash = ? AND revoked_at IS NOT NULL LIMIT 1",
    )
    .bind(public_key_hash.as_slice())
    .fetch_optional(database)
    .await?
    .is_some())
}

pub async fn publish_node_descriptor(
    id: IotaId,
    wire: iota_identity::NodeDescriptorWireV1,
) -> Result<iota_identity::NodeDescriptorWireV1> {
    let encoded =
        serde_json::to_string(&wire).map_err(|error| OmegaError::Validation(error.to_string()))?;
    let mut transaction = pool().await?.begin().await?;
    let row = sqlx::query(
        "SELECT public_key, node_descriptor, node_descriptor_revision \
         FROM iotas WHERE id = ? FOR UPDATE",
    )
    .bind(id.0)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(OmegaError::NotFound)?;
    let registered_key = PublicKeyBundle::from_bytes(&row.get::<Vec<u8>, _>("public_key"))
        .map_err(|error| OmegaError::Validation(error.to_string()))?;
    let current_descriptor: Option<String> = row.get("node_descriptor");
    let current_revision: Option<i64> = row.get("node_descriptor_revision");
    let verified = verify_published_node_descriptor(
        wire.clone(),
        &registered_key,
        current_revision,
        current_descriptor.as_deref(),
        &encoded,
        now_millis(),
    )?;
    sqlx::query(
        "UPDATE iotas SET node_id = ?, node_descriptor = ?, \
         node_descriptor_revision = ?, node_descriptor_valid_until = ? WHERE id = ?",
    )
    .bind(verified.descriptor().node.as_str())
    .bind(encoded)
    .bind(verified.descriptor().revision)
    .bind(verified.descriptor().valid_until)
    .bind(id.0)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(wire)
}

fn verify_published_node_descriptor(
    wire: iota_identity::NodeDescriptorWireV1,
    registered_key: &PublicKeyBundle,
    current_revision: Option<i64>,
    current_descriptor: Option<&str>,
    encoded: &str,
    now: i64,
) -> Result<iota_identity::VerifiedNodeDescriptor> {
    if current_revision == Some(wire.revision)
        && current_descriptor.is_some_and(|current| current != encoded)
    {
        return Err(OmegaError::Validation(
            "node descriptor revision was reused with different content".into(),
        ));
    }
    let verified = wire
        .parse()
        .and_then(|descriptor| descriptor.verify(current_revision, now))
        .map_err(|error| OmegaError::Validation(error.to_string()))?;
    if verified
        .descriptor()
        .public_keys
        .try_as_bytes()
        .map_err(|error| OmegaError::Validation(error.to_string()))?
        != registered_key.try_as_bytes()?
    {
        return Err(OmegaError::Validation(
            "node descriptor key does not match registered Iota key".into(),
        ));
    }
    Ok(verified)
}

pub async fn get_node_descriptor(id: IotaId) -> Result<iota_identity::NodeDescriptorWireV1> {
    let encoded =
        sqlx::query_scalar::<_, Option<String>>("SELECT node_descriptor FROM iotas WHERE id = ?")
            .bind(id.0)
            .fetch_optional(&pool().await?)
            .await?
            .ok_or(OmegaError::NotFound)?
            .ok_or(OmegaError::NotFound)?;
    serde_json::from_str(&encoded).map_err(|error| OmegaError::Validation(error.to_string()))
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub async fn get_iota_by_id(id: IotaId) -> Result<Iota> {
    get_iota_by_id_with_pool(&pool().await?, id).await
}

async fn get_iota_by_id_with_pool(database: &crate::db::DbPool, id: IotaId) -> Result<Iota> {
    let row = sqlx::query("SELECT id, public_key FROM iotas WHERE id = ?")
        .bind(id.0)
        .fetch_optional(database)
        .await?
        .ok_or(OmegaError::NotFound)?;
    let key = PublicKeyBundle::from_bytes(&row.get::<Vec<u8>, _>("public_key"))
        .map_err(|error| OmegaError::Validation(error.to_string()))?;
    Ok(Iota {
        id: row.get::<i64, _>("id").into(),
        public_key: key,
    })
}

pub async fn get_or_create_iota(public_key: PublicKeyBundle) -> Result<IotaId> {
    get_or_create_iota_with_pool(&pool().await?, public_key).await
}

async fn get_or_create_iota_with_pool(
    database: &crate::db::DbPool,
    public_key: PublicKeyBundle,
) -> Result<IotaId> {
    let (public_key_bytes, public_key_hash) = public_key_identity(&public_key)?;

    for _ in 0..16 {
        let mut transaction = database.begin().await?;
        lock_key_authority(&mut transaction, &public_key_hash).await?;
        if is_revoked(&mut transaction, &public_key_hash).await? {
            return Err(OmegaError::Validation(
                "Iota credential has been revoked".into(),
            ));
        }
        if let Some(existing) =
            get_iota_by_public_key_hash(&mut transaction, &public_key_hash).await?
        {
            if existing.public_key_bytes != public_key_bytes {
                return Err(OmegaError::Validation(
                    "Iota public-key hash collision".into(),
                ));
            }
            transaction.commit().await?;
            return Ok(existing.id);
        }

        let id = crate::db::user_repo::generate_protocol_id();
        let iota_id = IotaId::from(id.0);
        let result =
            sqlx::query("INSERT INTO iotas (id, public_key, public_key_hash) VALUES (?, ?, ?)")
                .bind(iota_id.0)
                .bind(&public_key_bytes)
                .bind(public_key_hash.as_slice())
                .execute(&mut *transaction)
                .await;

        match result {
            Ok(_) => {
                transaction.commit().await?;
                return Ok(iota_id);
            }
            Err(error) if crate::db::user_repo::is_duplicate_key(&error) => {
                if let Some(existing) =
                    get_iota_by_public_key_hash(&mut transaction, &public_key_hash).await?
                {
                    if existing.public_key_bytes != public_key_bytes {
                        return Err(OmegaError::Validation(
                            "Iota public-key hash collision".into(),
                        ));
                    }
                    transaction.commit().await?;
                    return Ok(existing.id);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(OmegaError::Validation(
        "could not allocate a unique Iota ID".into(),
    ))
}

pub async fn delete_iota(id: IotaId) -> Result<()> {
    delete_iota_with_pool(&pool().await?, id).await
}

async fn delete_iota_with_pool(database: &crate::db::DbPool, id: IotaId) -> Result<()> {
    let expected_public_key_hash =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT public_key_hash FROM iotas WHERE id = ?")
            .bind(id.0)
            .fetch_optional(database)
            .await?
            .ok_or(OmegaError::NotFound)?;
    let expected_public_key_hash: [u8; 32] = expected_public_key_hash.try_into().map_err(|_| {
        OmegaError::Validation("stored Iota public-key hash has invalid length".into())
    })?;
    let mut transaction = database.begin().await?;
    lock_key_authority(&mut transaction, &expected_public_key_hash).await?;
    let public_key_hash = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT public_key_hash FROM iotas WHERE id = ? FOR UPDATE",
    )
    .bind(id.0)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(OmegaError::NotFound)?;
    if public_key_hash.as_slice() != expected_public_key_hash {
        return Err(OmegaError::Validation(
            "Iota public key changed during deletion".into(),
        ));
    }
    let pending_erasure =
        sqlx::query("SELECT 1 FROM pending_iota_user_erasure WHERE iota_id = ? LIMIT 1 FOR UPDATE")
            .bind(id.0)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
    let pending_provisioning = sqlx::query(
        "SELECT 1 FROM pending_iota_user_provisioning WHERE iota_id = ? LIMIT 1 FOR UPDATE",
    )
    .bind(id.0)
    .fetch_optional(&mut *transaction)
    .await?
    .is_some();
    if pending_erasure || pending_provisioning {
        return Err(OmegaError::Validation(
            "Iota has pending hosted-data work".into(),
        ));
    }
    sqlx::query("DELETE FROM registration_leases WHERE iota_id = ?")
        .bind(id.0)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM iota_snapshot_outbox WHERE iota_id = ?")
        .bind(id.0)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE iota_key_authority \
         SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP(3)) \
         WHERE public_key_hash = ?",
    )
    .bind(&public_key_hash)
    .execute(&mut *transaction)
    .await?;
    let result = sqlx::query("DELETE FROM iotas WHERE id = ?")
        .bind(id.0)
        .execute(&mut *transaction)
        .await?;
    if result.rows_affected() == 0 {
        return Err(OmegaError::NotFound);
    }
    transaction.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iota_identity::{LocalNodeIdentity, NodeDescriptor, SignedNodeDescriptor};
    use mtp::crypto::Keyring;
    use sqlx::mysql::MySqlPoolOptions;

    async fn test_pool() -> std::result::Result<crate::db::DbPool, Box<dyn std::error::Error>> {
        let database = MySqlPoolOptions::new()
            .max_connections(4)
            .connect(&std::env::var("TEST_DB_URL")?)
            .await?;
        crate::db::initialize_schema(&database).await?;
        Ok(database)
    }

    async fn remove_test_key(
        database: &crate::db::DbPool,
        public_key: &PublicKeyBundle,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (_, hash) = public_key_identity(public_key)?;
        sqlx::query("DELETE FROM iotas WHERE public_key_hash = ?")
            .bind(hash.as_slice())
            .execute(database)
            .await?;
        sqlx::query("DELETE FROM iota_key_authority WHERE public_key_hash = ?")
            .bind(hash.as_slice())
            .execute(database)
            .await?;
        Ok(())
    }

    #[test]
    fn node_publication_requires_registered_key_and_new_revision() {
        let identity = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
        let now = now_millis();
        let wire = SignedNodeDescriptor::sign(
            NodeDescriptor {
                node: identity.node_id().clone(),
                public_keys: identity.public_keys(),
                direct_endpoints: Vec::new(),
                relay_hints: Vec::new(),
                revision: 2,
                valid_until: Some(now + 60_000),
            },
            &identity,
        )
        .unwrap()
        .to_wire_v1()
        .unwrap();
        let encoded = serde_json::to_string(&wire).unwrap();
        assert!(
            verify_published_node_descriptor(
                wire.clone(),
                &identity.public_keys(),
                Some(1),
                None,
                &encoded,
                now,
            )
            .is_ok()
        );
        assert!(
            verify_published_node_descriptor(
                wire.clone(),
                &Keyring::generate().public_key_bundle(),
                Some(1),
                None,
                &encoded,
                now,
            )
            .is_err()
        );
        assert!(
            verify_published_node_descriptor(
                wire,
                &identity.public_keys(),
                Some(3),
                None,
                &encoded,
                now,
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DB_URL pointing to a disposable migrated MySQL database"]
    async fn registration_retry_after_lost_response_returns_committed_identity()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let database = test_pool().await?;
        let public_key = Keyring::generate().public_key_bundle();

        let first = get_or_create_iota_with_pool(&database, public_key.clone()).await?;
        let second = get_or_create_iota_with_pool(&database, public_key.clone()).await?;
        let (_, hash) = public_key_identity(&public_key)?;
        let identities =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM iotas WHERE public_key_hash = ?")
                .bind(hash.as_slice())
                .fetch_one(&database)
                .await?;

        assert_eq!(first, second);
        assert_eq!(identities, 1);
        remove_test_key(&database, &public_key).await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DB_URL pointing to a disposable migrated MySQL database"]
    async fn concurrent_registration_returns_one_identity()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let database = test_pool().await?;
        let public_key = Keyring::generate().public_key_bundle();
        let left = get_or_create_iota_with_pool(&database, public_key.clone());
        let right = get_or_create_iota_with_pool(&database, public_key.clone());
        let (left, right) = tokio::try_join!(left, right)?;

        assert_eq!(left, right);
        remove_test_key(&database, &public_key).await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DB_URL pointing to a disposable migrated MySQL database"]
    async fn different_keys_receive_different_identities()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let database = test_pool().await?;
        let first_key = Keyring::generate().public_key_bundle();
        let second_key = Keyring::generate().public_key_bundle();
        let first = get_or_create_iota_with_pool(&database, first_key.clone()).await?;
        let second = get_or_create_iota_with_pool(&database, second_key.clone()).await?;

        assert_ne!(first, second);
        remove_test_key(&database, &first_key).await?;
        remove_test_key(&database, &second_key).await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DB_URL pointing to a disposable migrated MySQL database"]
    async fn deleted_iota_is_not_active_and_key_cannot_register_again()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let database = test_pool().await?;
        let public_key = Keyring::generate().public_key_bundle();
        let id = get_or_create_iota_with_pool(&database, public_key.clone()).await?;

        delete_iota_with_pool(&database, id).await?;
        assert!(matches!(
            get_iota_by_id_with_pool(&database, id).await,
            Err(OmegaError::NotFound)
        ));
        let result = get_or_create_iota_with_pool(&database, public_key.clone()).await;

        assert!(
            matches!(result, Err(OmegaError::Validation(message)) if message == "Iota credential has been revoked")
        );
        remove_test_key(&database, &public_key).await?;
        Ok(())
    }
}
