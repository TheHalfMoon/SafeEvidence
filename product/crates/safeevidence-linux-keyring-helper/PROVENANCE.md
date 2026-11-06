# Provenance: safeevidence-linux-keyring-helper

Admission `ADM-0003` (T03), adapted from `TheHalfMoon/ottari` @ `73706029849bcbe51243624e37f03a1969dc74ca`, `crates/himsat-core/src/vault_linux_secret_service.rs`, Apache-2.0.

The founder chose a separate helper process on 2026-11-06, so that the core stays socket-free. This crate holds the donor adapter's Secret Service calls and its item checks. It does not depend on the vault, and it stores
an opaque record. The record format and the binding and policy checks stay in `safeevidence-vault`.

## Limits

- It connects to the session bus through `zbus`, and so opens sockets in this process, as intended. `zbus` also contains TCP transport code.
- The vault spawns it by absolute path with a cleared environment, and does not check its digest. Anyone who can replace the file already acts as this user.
- Records cross an OS pipe between two same-user processes. Frames are zeroized in each process, and the pipe buffer is outside that.
- A locked collection is refused rather than unlocked. A provider prompt could hold a request until the vault's reply timeout.
- Packaging is not done: nothing yet installs this binary beside the app, and the desktop shell does not use the protector.
