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
    sqlx::raw_sql(include_str!("schema.sql"))
        .execute(pool)
        .await?;
    Ok(())
}
