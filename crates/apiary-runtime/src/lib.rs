//! apiary-runtime — inference in, connections out (SPEC §1).
//!
//! The core (apiary-core) has custody; this crate has the loop. Inference is
//! just the connection wired to the cognition port: providers are swappable,
//! routing is declarative policy decided before inference, and spend floors
//! are enforced here in Rust — the model is never asked to be frugal.

pub mod acp;
pub mod buzz;
pub mod connector;
pub mod huddle;
pub mod index;
pub mod inference;
pub mod lease;
pub mod mcp;
pub mod plugin;
pub mod presence;
pub mod proposal;
pub mod publish;
pub mod relay;
pub mod routines;
pub mod routing;
pub mod runner;
pub mod slack;
pub mod speak;
pub mod spend;
pub mod telegram;
pub mod transcribe;
pub mod watches;
pub mod vault;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] apiary_core::Error),
    #[error("provider: {0}")]
    Provider(String),
    #[error("routing: {0}")]
    Routing(String),
    #[error("budget: {0}")]
    Budget(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
