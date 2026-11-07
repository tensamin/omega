use crate::error::{OmegaError, Result};
use once_cell::sync::Lazy;
use sqlx::{MySql, Pool, mysql::MySqlPoolOptions};
use std::{env, sync::Arc};
use tokio::sync::RwLock;

pub mod invitation_repo;
pub mod iota_repo;
pub mod notification_repo;
pub mod omikron_repo;
pub mod short_link_repo;
pub mod user_repo;

pub type DbPool = Pool<MySql>;
const STORAGE_FORMAT: &str = "omega-storage:1";

static POOL: Lazy<Arc<RwLock<Option<DbPool>>>> = Lazy::new(|| Arc::new(RwLock::new(None)));

pub async fn pool() -> Result<DbPool> {
    POOL.read()
        .await
        .as_ref()
        .cloned()
        .ok_or(OmegaError::DatabaseNotInitialized)
}

pub async fn initialize(config: &crate::config::DatabaseConfig) -> Result<()> {
    let url =
        env::var("DB_URL").map_err(|_| OmegaError::Validation("DB_URL is not set".to_string()))?;
    let pool = MySqlPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .idle_timeout(config.idle_timeout)
        .max_lifetime(config.max_lifetime)
        .connect(&url)
        .await?;
    initialize_schema(&pool).await?;
    *POOL.write().await = Some(pool);
    Ok(())
}

pub(crate) async fn initialize_schema(pool: &DbPool) -> Result<()> {
    let (has_tables, has_marker): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE()),
         EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='omega_storage_format')",
    ).fetch_one(pool).await?;
    let incompatible = || {
        OmegaError::Validation(
        "incompatible database format; initialize a fresh Omega database instead of upgrading this store".into(),
    )
    };
    if has_tables {
        if !has_marker {
            return Err(incompatible());
        }
        let format: Option<String> =
            sqlx::query_scalar("SELECT format_name FROM omega_storage_format WHERE singleton=1")
                .fetch_optional(pool)
                .await?;
        return if format.as_deref() == Some(STORAGE_FORMAT) {
            Ok(())
        } else {
            Err(incompatible())
        };
    }
    sqlx::raw_sql(include_str!("schema.sql"))
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO omega_storage_format(singleton,format_name) VALUES(1,?)")
        .bind(STORAGE_FORMAT)
        .execute(pool)
        .await?;
    Ok(())
}
