use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity storage error at {path}: {source}")]
    Storage {
        path: PathBuf,
        #[source]
        source: mtp::files::FileError,
    },
    #[error("identity I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("public key bundle at {path} does not match the private keyring")]
    PublicBundleMismatch { path: PathBuf },
}

#[derive(Debug, Error)]
pub enum OmegaError {
    #[error("database pool is not initialized")]
    DatabaseNotInitialized,
    #[error("database error: {0}")]
    Database(sqlx::Error),
    #[error("cryptographic error: {0}")]
    Crypto(#[from] mtp::crypto::CryptoError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("invalid input: {0}")]
    Validation(String),
    #[error("resource not found")]
    NotFound,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("not connected")]
    NotConnected,
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("invalid response")]
    InvalidResponse,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("invitation error: {0}")]
    Invitation(&'static str),
    #[error("send error: {0}")]
    SendError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, OmegaError>;

impl From<sqlx::Error> for OmegaError {
    fn from(error: sqlx::Error) -> Self {
        if matches!(error, sqlx::Error::RowNotFound) {
            Self::NotFound
        } else {
            Self::Database(error)
        }
    }
}

impl OmegaError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) | Self::Invitation(_) => "invalid_request",
            Self::NotFound => "not_found",
            Self::DatabaseNotInitialized
            | Self::Database(
                sqlx::Error::PoolTimedOut
                | sqlx::Error::PoolClosed
                | sqlx::Error::Io(_)
                | sqlx::Error::Tls(_),
            ) => "database_unavailable",
            Self::Database(_) => "database_failed",
            Self::NotAuthenticated | Self::AuthenticationFailed => "authentication_required",
            Self::Transport(_) | Self::NotConnected | Self::SendError(_) => {
                "dependency_unavailable"
            }
            Self::InvalidResponse => "invalid_upstream_response",
            Self::Crypto(_) | Self::Identity(_) | Self::Io(_) => "internal_error",
        }
    }

    pub fn status_code(&self) -> http::StatusCode {
        match self {
            Self::Validation(_) | Self::Invitation(_) => http::StatusCode::BAD_REQUEST,
            Self::NotFound => http::StatusCode::NOT_FOUND,
            Self::NotAuthenticated | Self::AuthenticationFailed => http::StatusCode::UNAUTHORIZED,
            Self::DatabaseNotInitialized
            | Self::Database(
                sqlx::Error::PoolTimedOut
                | sqlx::Error::PoolClosed
                | sqlx::Error::Io(_)
                | sqlx::Error::Tls(_),
            )
            | Self::Transport(_)
            | Self::NotConnected
            | Self::SendError(_) => http::StatusCode::SERVICE_UNAVAILABLE,
            Self::InvalidResponse => http::StatusCode::BAD_GATEWAY,
            Self::Database(_) | Self::Crypto(_) | Self::Identity(_) | Self::Io(_) => {
                http::StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}
