//! Secret Service access for the Linux keyring helper.
//!
//! Adapted from T03's Linux adapter (`ADM-0009`). It uses only the default collection and negotiates the
//! encrypted Diffie-Hellman session. Provider-visible metadata is limited to one fixed application
//! identifier, one fixed item label and content type, and one opaque protector identifier. It never
//! unlocks a locked collection or item, and never uses the plaintext Secret Service session. It stores
//! an opaque record: binding and policy checks are the vault's.

#[cfg(target_os = "linux")]
mod secret_service_backend;

#[cfg(target_os = "linux")]
pub use secret_service_backend::*;

#[cfg(test)]
mod tests {
    /// A buffered reader would keep whole records in std's buffer after the frames are zeroized. A review
    /// showed that with a memory scan; this guards the shape, since no test here scans memory.
    #[test]
    fn main_serves_over_unbuffered_handles() {
        let main = include_str!("main.rs");
        assert!(main.contains("File::from(stdin)") && main.contains("File::from(stdout)"));
        assert!(!main.contains(".lock()"));
        assert!(!main.contains("BufReader") && !main.contains("BufWriter"));
    }
}
