mod api;
mod config;
mod db;
pub mod error;
mod identity;
mod models;
mod server;
mod sql;
mod state;
mod transport;
mod util;

pub use error::{OmegaError, Result};

use crate::db::initialize;
use crate::state::{OmegaState, spawn_challenge_cleanup};
use crate::transport::omikron_connection;
use crate::transport::omikron_manager;
use crate::util::file_util::get_directory;
use crate::util::logger::PrintType;
use crate::util::logger::startup;
use crate::{config::OmegaConfig, server::middleware};
use dotenv::from_path;
use rustls::crypto::aws_lc_rs::default_provider;
use std::env;
use std::path::Path;
use std::time::Duration;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    if default_provider().install_default().is_err() {
        println!("Error loading Provider");
        return;
    }
    let _ = from_path(Path::new(&get_directory()).join(".env"));
    let config = match OmegaConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("[FATAL] Omega configuration is invalid: {error}");
            return;
        }
    };
    let _logger_guard = match startup(config.logger_queue_capacity) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("[FATAL] Unable to initialize Omega logger: {error}");
            return;
        }
    };
    log_in!("Incoming messages");
    log_out!("Outgoing messages");
    if middleware::initialize_config(config.rate_limits.clone()).is_err() {
        log!("[FATAL] Omega rate-limit configuration was initialized more than once");
        return;
    }
    let identity = match identity::OmegaIdentity::load_or_create() {
        Ok(identity) => identity,
        Err(error) => {
            log!("[FATAL] Omega identity initialization failed: {}", error);
            return;
        }
    };
    let database_config = config.database.clone();
    let state = OmegaState::new(identity, config);

    log!("Started");
    log!("  .env");
    if let Err(e) = initialize(&database_config).await {
        log!("[FATAL] Database initialization failed: {}", e);
        log!(
            "[FATAL] Please ensure the database is running and the .env file is configured correctly."
        );
        return;
    } else {
        log!("  DB");
    }
    let rate_limit_cleanup = crate::server::middleware::spawn_cleanup_task();
    let challenge_cleanup = spawn_challenge_cleanup(state.clone());
    let short_link_cleanup = tokio::spawn(async {
        let mut ticker = interval(Duration::from_secs(24 * 60 * 60));
        loop {
            ticker.tick().await;
            if let Err(error) = crate::db::short_link_repo::delete_expired().await {
                log_err!(
                    0,
                    PrintType::General,
                    "Short-link cleanup failed: {}",
                    error
                );
            }
        }
    });
    let snapshot_outbox_worker = omikron_manager::spawn_iota_snapshot_outbox_worker(state.clone());
    let provisioning_outbox_worker =
        omikron_manager::spawn_user_provisioning_outbox_worker(state.clone());
    let erasure_outbox_worker = omikron_manager::spawn_user_erasure_outbox_worker(state.clone());
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(443);

    let shutdown = CancellationToken::new();
    let server = omikron_connection::start(port, state, shutdown.clone());
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            if let Err(e) = result {
                log_err!(0, PrintType::General, "Server error: {:?}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            log!("Shutting down on signal...");
            shutdown.cancel();
            if let Err(e) = server.await {
                log_err!(0, PrintType::General, "Server shutdown error: {:?}", e);
            }
        }
    }
    rate_limit_cleanup.abort();
    challenge_cleanup.abort();
    short_link_cleanup.abort();
    snapshot_outbox_worker.abort();
    provisioning_outbox_worker.abort();
    erasure_outbox_worker.abort();
}
