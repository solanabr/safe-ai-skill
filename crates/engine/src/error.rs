//! Engine-wide error type and result alias.
//!
//! Kept deliberately small. The engine never panics on bad input; callers convert
//! errors into a conservative [`crate::io::Decision`] at the dispatch layer.

use std::fmt;

/// Engine-wide error type.
#[derive(Debug)]
pub enum Error {
    /// Filesystem / stdin I/O failure.
    Io(std::io::Error),
    /// A parse failure (YAML, JSON, command tokenization, etc.). Carries a human message.
    Parse(String),
    /// A network failure (osv.dev, rugcheck, provenance lookups). Carries a human message.
    Network(String),
    /// Any other failure that does not fit the categories above.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Parse(m) => write!(f, "parse error: {m}"),
            Error::Network(m) => write!(f, "network error: {m}"),
            Error::Other(m) => write!(f, "error: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;
