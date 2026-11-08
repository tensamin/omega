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
    let stop_signal = match shutdown_signal() {
        Ok(signal) => signal,
        Err(error) => {
            eprintln!("Unable to install shutdown signal handler: {error}");
            return;
        }
    };
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
        result = stop_signal => {
            if let Err(error) = result {
                log_err!(0, PrintType::General, "Shutdown signal listener failed: {error}");
            }
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

fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = std::io::Result<()>>> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        #[cfg(unix)]
        {
            tokio::select! {
                result = tokio::signal::ctrl_c() => result,
                _ = terminate.recv() => Ok(()),
            }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sigterm_uses_shutdown_path() {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;
        use tokio::time::{Duration, timeout};
        if std::env::var_os("TENSAMIN_SHUTDOWN_TEST_CHILD").is_some() {
            let signal = shutdown_signal().unwrap();
            println!("shutdown handler ready");
            timeout(Duration::from_secs(5), signal)
                .await
                .expect("SIGTERM was not observed")
                .unwrap();
            return;
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::sigterm_uses_shutdown_path",
                "--nocapture",
            ])
            .env("TENSAMIN_SHUTDOWN_TEST_CHILD", "1")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
        let ready = timeout(Duration::from_secs(10), async {
            while let Some(line) = output.next_line().await.unwrap() {
                if line == "shutdown handler ready" {
                    return true;
                }
            }
            false
        })
        .await;
        if !matches!(ready, Ok(true)) {
            let _ = child.kill().await;
            panic!("child did not register its shutdown handler");
        }
        assert!(
            Command::new("kill")
                .args(["-TERM", &child.id().unwrap().to_string()])
                .status()
                .await
                .unwrap()
                .success()
        );
        let status = match timeout(Duration::from_secs(10), child.wait()).await {
            Ok(status) => status.unwrap(),
            Err(_) => {
                let _ = child.kill().await;
                panic!("child did not exit after SIGTERM");
            }
        };
        assert!(status.success());
    }
}
