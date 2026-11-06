//! Secret Service access for the Linux keyring helper.
//!
//! Adapted from T03's Linux adapter (`ADM-0003`). It uses only the default collection and negotiates the
//! encrypted Diffie-Hellman session. Provider-visible metadata is limited to one fixed application
//! identifier, one fixed item label and content type, and one opaque protector identifier. It never
//! unlocks a locked collection or item, and never uses the plaintext Secret Service session. It stores
//! an opaque record: binding and policy checks are the vault's.

#[cfg(target_os = "linux")]
mod secret_service_backend;

#[cfg(target_os = "linux")]
pub use secret_service_backend::*;
