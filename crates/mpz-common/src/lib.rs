//! Common functionality for `mpz`.
//!
//! This crate provides various common functionalities needed for modeling
//! protocol execution, I/O, and multi-threading.
//!
//! This crate does not provide any cryptographic primitives, see `mpz-core` for
//! that.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

mod context;
#[cfg(any(test, feature = "cpu"))]
pub mod cpu;
#[cfg(any(test, feature = "executor"))]
pub mod executor;
#[cfg(any(test, feature = "future"))]
pub mod future;
mod id;
#[cfg(any(test, feature = "ideal"))]
pub mod ideal;
#[cfg(any(test, feature = "executor"))]
pub(crate) mod load_balance;
#[cfg(feature = "sync")]
pub mod sync;

pub use context::{Context, ContextError};
pub use id::{Counter, ThreadId};
// Re-export scoped-futures for use with the callback-like API in `Context`.
pub use scoped_futures;

use async_trait::async_trait;

/// A functionality that can be flushed.
#[async_trait]
pub trait Flush<Ctx> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns `true` if the functionality wants to be flushed.
    fn wants_flush(&self) -> bool;

    /// Flushes the functionality.
    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error>;
}
