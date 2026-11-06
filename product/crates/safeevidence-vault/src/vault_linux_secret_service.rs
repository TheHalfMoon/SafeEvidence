//! Linux Secret Service adapter for Specification 004B4 B404, through a helper process.
//!
//! The core opens no sockets, so `safeevidence-linux-keyring-helper` holds the Secret Service and D-Bus
//! code, and this side talks to it over stdin and stdout. This side keeps the record format, the binding
//! to vault, generation and policy, and the capability claims. Vault identity, key generation, policy
//! binding, and VRK bytes stay inside the record, which the helper treats as opaque.
//!
//! The baseline reports `SAME_USER_SESSION`, no per-SafeEvidence-unlock user presence, and unknown
//! hardware backing. It does not implement freshness-anchor or protector-replacement semantics.

use crate::vault::{
    AccessScope, FreshnessAnchor, HardwareBacking, KeyGeneration, ProtectedFreshnessState,
    ProtectorCapabilities, ProtectorError, SecretProtector, UserPresencePolicy, VaultId,
};
use crate::vault_keys::{KEY_MATERIAL_BYTES, OwnedKeyMaterial};
use crate::vault_protector::{ProtectorPolicy, validate_requested_policy};
use getrandom::fill;
use safeevidence_keyring_wire::{
    Op, PROTECTOR_ID_BYTES, ProtectorId, Reply, Request, SecretBytes, WireError, decode_reply,
    encode_request, read_frame, write_frame,
};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;
use zeroize::Zeroizing;

const RECORD_MAGIC: &[u8] = b"HIMSAT/LINUX/SECRET-SERVICE/VRK/v1\0";
const OWNER_TAG: &[u8] = b"HIMSAT/APP/v1\0";
const RECORD_BYTES: usize =
    RECORD_MAGIC.len() + OWNER_TAG.len() + 16 + 8 + 1 + 1 + KEY_MATERIAL_BYTES;
const HELPER_NAME: &str = "safeevidence-linux-keyring-helper";
const DEFAULT_REPLY_TIMEOUT: Duration = Duration::from_secs(120);
/// All the helper may inherit: what `zbus` needs to find and authenticate to the session bus.
const HELPER_ENVIRONMENT: [&str; 3] = ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "HOME"];

/// Opaque provider-visible identifier used only as a Secret Service attribute.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LinuxProtectorId([u8; PROTECTOR_ID_BYTES]);

impl LinuxProtectorId {
    /// Generates a new opaque protector identifier from the reviewed OS CSPRNG.
    pub fn generate() -> Result<Self, ProtectorError> {
        let mut bytes = [0_u8; PROTECTOR_ID_BYTES];
        fill(&mut bytes).map_err(|_| ProtectorError::Unavailable)?;
        Ok(Self(bytes))
    }

    /// Reconstructs a previously persisted opaque protector identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PROTECTOR_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque bytes for SafeEvidence-owned metadata persistence.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROTECTOR_ID_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for LinuxProtectorId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("LinuxProtectorId([OPAQUE; 16 bytes])")
    }
}

/// Immutable Linux Secret Service configuration for one opaque protector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSecretServiceConfig {
    protector_id: LinuxProtectorId,
}

impl LinuxSecretServiceConfig {
    /// Creates configuration for one opaque Secret Service protector item.
    #[must_use]
    pub const fn new(protector_id: LinuxProtectorId) -> Self {
        Self { protector_id }
    }

    /// Returns the opaque provider lookup identifier.
    #[must_use]
    pub const fn protector_id(self) -> LinuxProtectorId {
        self.protector_id
    }
}

/// How to start the helper: an absolute path only, never a `PATH` lookup.
#[derive(Clone, Debug)]
pub struct KeyringHelperCommand {
    path: PathBuf,
    arguments: Vec<String>,
    reply_timeout: Duration,
}

impl KeyringHelperCommand {
    /// # Errors
    /// Returns `Unavailable` unless the path is absolute.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ProtectorError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(ProtectorError::Unavailable);
        }
        Ok(Self {
            path: path.to_path_buf(),
            arguments: Vec::new(),
            reply_timeout: DEFAULT_REPLY_TIMEOUT,
        })
    }

    /// The helper installed next to the running executable.
    ///
    /// # Errors
    /// Returns `Unavailable` if the running executable's directory cannot be found.
    pub fn beside_current_exe() -> Result<Self, ProtectorError> {
        let exe = std::env::current_exe().map_err(|_| ProtectorError::Unavailable)?;
        let directory = exe.parent().ok_or(ProtectorError::Unavailable)?;
        Self::new(directory.join(format!("{HELPER_NAME}{}", std::env::consts::EXE_SUFFIX)))
    }

    /// Sets how long one reply may take before the helper is killed and the call fails.
    #[must_use]
    pub const fn with_reply_timeout(mut self, reply_timeout: Duration) -> Self {
        self.reply_timeout = reply_timeout;
        self
    }

    /// Passes an argument to the program. The real helper takes none; tests use this to pick a fake's mode.
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_argument(mut self, argument: &str) -> Self {
        self.arguments.push(argument.to_owned());
        self
    }
}

/// The record store behind the protector.
trait RecordStore: Send {
    fn ensure_unlocked(&mut self, id: &ProtectorId) -> Result<(), ProtectorError>;
    fn read(&mut self, id: &ProtectorId) -> Result<Option<SecretBytes>, ProtectorError>;
    fn create(&mut self, id: &ProtectorId, record: &[u8]) -> Result<(), ProtectorError>;
    fn delete(&mut self, id: &ProtectorId) -> Result<(), ProtectorError>;
}

const fn protector_error(error: WireError) -> ProtectorError {
    match error {
        WireError::Unavailable => ProtectorError::Unavailable,
        WireError::Locked => ProtectorError::Locked,
        WireError::Denied => ProtectorError::Denied,
        WireError::ItemMissing => ProtectorError::ItemMissing,
        WireError::OwnerMismatch => ProtectorError::OwnerMismatch,
        WireError::PolicyMismatch => ProtectorError::PolicyMismatch,
        WireError::CorruptOrTampered | WireError::Protocol => ProtectorError::CorruptOrTampered,
    }
}

struct HelperSession {
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<std::io::Result<Option<SecretBytes>>>,
}

impl Drop for HelperSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The helper process. It starts on first use, and any failed exchange ends it, so the next call starts
/// a new one. A failure is never treated as a reply.
struct HelperProcess {
    command: KeyringHelperCommand,
    session: Option<HelperSession>,
}

impl HelperProcess {
    fn spawn(&self) -> Result<HelperSession, ProtectorError> {
        let mut command = Command::new(&self.command.path);
        command
            .args(&self.command.arguments)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for name in HELPER_ENVIRONMENT {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = command.spawn().map_err(|_| ProtectorError::Unavailable)?;
        let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let (Some(stdin), Some(mut stdout)) = (stdin, stdout) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProtectorError::Unavailable);
        };
        let (sender, replies) = channel();
        // A thread, so a helper that stops answering can time out instead of hanging the vault.
        std::thread::spawn(move || {
            loop {
                let frame = read_frame(&mut stdout);
                let done = !matches!(frame, Ok(Some(_)));
                if sender.send(frame).is_err() || done {
                    return;
                }
            }
        });
        Ok(HelperSession {
            child,
            stdin,
            replies,
        })
    }

    fn call(&mut self, request: &Request) -> Result<Reply, ProtectorError> {
        if self.session.is_none() {
            self.session = Some(self.spawn()?);
        }
        let result = self.exchange(request);
        if result.is_err() {
            self.session = None;
        }
        result
    }

    fn exchange(&mut self, request: &Request) -> Result<Reply, ProtectorError> {
        let session = self.session.as_mut().ok_or(ProtectorError::Unavailable)?;
        write_frame(&mut session.stdin, &encode_request(request))
            .map_err(|_| ProtectorError::Unavailable)?;
        let frame = session
            .replies
            .recv_timeout(self.command.reply_timeout)
            .map_err(|_| ProtectorError::Unavailable)?
            .map_err(|_| ProtectorError::Unavailable)?
            .ok_or(ProtectorError::Unavailable)?;
        decode_reply(&frame).map_err(protector_error)
    }

    fn call_done(&mut self, request: &Request) -> Result<(), ProtectorError> {
        match self.call(request)? {
            Reply::Done => Ok(()),
            Reply::Failed(error) => Err(protector_error(error)),
            Reply::NoRecord | Reply::Record(_) => {
                self.session = None;
                Err(ProtectorError::CorruptOrTampered)
            }
        }
    }
}

impl RecordStore for HelperProcess {
    fn ensure_unlocked(&mut self, id: &ProtectorId) -> Result<(), ProtectorError> {
        self.call_done(&Request {
            protector_id: *id,
            op: Op::EnsureUnlocked,
        })
    }

    fn read(&mut self, id: &ProtectorId) -> Result<Option<SecretBytes>, ProtectorError> {
        let reply = self.call(&Request {
            protector_id: *id,
            op: Op::Read,
        })?;
        match reply {
            Reply::NoRecord => Ok(None),
            Reply::Record(record) => Ok(Some(record)),
            Reply::Failed(error) => Err(protector_error(error)),
            Reply::Done => {
                self.session = None;
                Err(ProtectorError::CorruptOrTampered)
            }
        }
    }

    fn create(&mut self, id: &ProtectorId, record: &[u8]) -> Result<(), ProtectorError> {
        self.call_done(&Request {
            protector_id: *id,
            op: Op::Create(Zeroizing::new(record.to_vec())),
        })
    }

    fn delete(&mut self, id: &ProtectorId) -> Result<(), ProtectorError> {
        self.call_done(&Request {
            protector_id: *id,
            op: Op::Delete,
        })
    }
}

/// Linux Secret Service implementation of the portable `SecretProtector` contract.
pub struct LinuxSecretServiceProtector {
    config: LinuxSecretServiceConfig,
    policy: Option<ProtectorPolicy>,
    store: Box<dyn RecordStore>,
}

impl LinuxSecretServiceProtector {
    /// Creates an unconfigured conservative Linux adapter. The helper starts on first use.
    #[must_use]
    pub fn new(config: LinuxSecretServiceConfig, helper: KeyringHelperCommand) -> Self {
        Self {
            config,
            policy: None,
            store: Box::new(HelperProcess {
                command: helper,
                session: None,
            }),
        }
    }

    /// Returns the immutable native configuration used by this adapter.
    #[must_use]
    pub const fn config(&self) -> LinuxSecretServiceConfig {
        self.config
    }

    fn policy(&self) -> Result<ProtectorPolicy, ProtectorError> {
        self.policy.ok_or(ProtectorError::UnsupportedPolicy)
    }

    fn id(&self) -> ProtectorId {
        *self.config.protector_id().as_bytes()
    }

    fn read_record(&mut self) -> Result<Option<SecretBytes>, ProtectorError> {
        let id = self.id();
        let record = self.store.read(&id)?;
        if record
            .as_ref()
            .is_some_and(|record| record.len() != RECORD_BYTES)
        {
            return Err(ProtectorError::CorruptOrTampered);
        }
        Ok(record)
    }
}

impl SecretProtector for LinuxSecretServiceProtector {
    type VaultRootKey = OwnedKeyMaterial;

    fn create_protector(
        &mut self,
        requested_scope: AccessScope,
        user_presence_policy: UserPresencePolicy,
    ) -> Result<(), ProtectorError> {
        let policy = validate_linux_policy(requested_scope, user_presence_policy)?;
        let id = self.id();
        self.store.ensure_unlocked(&id)?;
        self.policy = Some(policy);
        Ok(())
    }

    fn protect_or_store_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
        vrk: &Self::VaultRootKey,
    ) -> Result<(), ProtectorError> {
        let policy = self.policy()?;
        if let Some(record) = self.read_record()? {
            validate_record_binding(&record, vault_id, Some(key_generation), policy)?;
            return if record_matches_vrk(&record, vrk)? {
                Ok(())
            } else {
                Err(ProtectorError::CorruptOrTampered)
            };
        }

        let record = Zeroizing::new(encode_record(vault_id, key_generation, policy, vrk));
        let id = self.id();
        self.store.create(&id, &record[..])?;
        let stored = self.read_record()?.ok_or(ProtectorError::ItemMissing)?;
        validate_record_binding(&stored, vault_id, Some(key_generation), policy)?;
        if !record_matches_vrk(&stored, vrk)? {
            return Err(ProtectorError::CorruptOrTampered);
        }
        Ok(())
    }

    fn unlock_vrk(
        &mut self,
        vault_id: VaultId,
        key_generation: KeyGeneration,
    ) -> Result<Self::VaultRootKey, ProtectorError> {
        let policy = self.policy()?;
        let record = self.read_record()?.ok_or(ProtectorError::ItemMissing)?;
        decode_record(&record, vault_id, key_generation, policy)
    }

    fn read_freshness_anchor(
        &self,
        _vault_id: VaultId,
    ) -> Result<ProtectedFreshnessState, ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn install_genesis_freshness_anchor(
        &mut self,
        _vault_id: VaultId,
        _expected_state: ProtectedFreshnessState,
        _new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn advance_freshness_anchor(
        &mut self,
        _vault_id: VaultId,
        _expected_old: FreshnessAnchor,
        _new_anchor: FreshnessAnchor,
    ) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn replace_protector(&mut self, _vault_id: VaultId) -> Result<(), ProtectorError> {
        Err(ProtectorError::UnsupportedPolicy)
    }

    fn remove_protector(&mut self, vault_id: VaultId) -> Result<(), ProtectorError> {
        let policy = self.policy()?;
        let Some(record) = self.read_record()? else {
            self.policy = None;
            return Ok(());
        };
        validate_record_binding(&record, vault_id, None, policy)?;
        let id = self.id();
        self.store.delete(&id)?;
        self.policy = None;
        Ok(())
    }

    fn actual_access_scope(&self) -> AccessScope {
        AccessScope::SameUserSession
    }

    fn requires_user_presence(&self) -> bool {
        false
    }

    fn hardware_backed_state(&self) -> HardwareBacking {
        HardwareBacking::Unknown
    }
}

fn validate_linux_policy(
    requested_scope: AccessScope,
    user_presence_policy: UserPresencePolicy,
) -> Result<ProtectorPolicy, ProtectorError> {
    let policy = ProtectorPolicy::new(requested_scope, user_presence_policy);
    validate_requested_policy(
        ProtectorCapabilities::new(
            AccessScope::SameUserSession,
            false,
            HardwareBacking::Unknown,
        ),
        policy,
    )?;
    Ok(policy)
}

fn encode_record(
    vault_id: VaultId,
    key_generation: KeyGeneration,
    policy: ProtectorPolicy,
    vrk: &OwnedKeyMaterial,
) -> [u8; RECORD_BYTES] {
    let mut output = [0_u8; RECORD_BYTES];
    let mut offset = 0;
    output[offset..offset + RECORD_MAGIC.len()].copy_from_slice(RECORD_MAGIC);
    offset += RECORD_MAGIC.len();
    output[offset..offset + OWNER_TAG.len()].copy_from_slice(OWNER_TAG);
    offset += OWNER_TAG.len();
    output[offset..offset + 16].copy_from_slice(vault_id.as_bytes());
    offset += 16;
    output[offset..offset + 8].copy_from_slice(&key_generation.get().to_be_bytes());
    offset += 8;
    output[offset] = encode_scope(policy.access_scope());
    offset += 1;
    output[offset] = encode_presence(policy.user_presence_policy());
    offset += 1;
    vrk.with_bytes(|bytes| output[offset..].copy_from_slice(bytes));
    output
}

fn record_binding(
    record: &[u8],
) -> Result<(VaultId, KeyGeneration, ProtectorPolicy), ProtectorError> {
    if record.len() != RECORD_BYTES || !record.starts_with(RECORD_MAGIC) {
        return Err(ProtectorError::CorruptOrTampered);
    }
    let mut offset = RECORD_MAGIC.len();
    if &record[offset..offset + OWNER_TAG.len()] != OWNER_TAG {
        return Err(ProtectorError::CorruptOrTampered);
    }
    offset += OWNER_TAG.len();
    let stored_vault = VaultId::try_from_slice(&record[offset..offset + 16])
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    offset += 16;
    let generation_bytes: [u8; 8] = record[offset..offset + 8]
        .try_into()
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    let stored_generation = KeyGeneration::new(u64::from_be_bytes(generation_bytes))
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    offset += 8;
    let stored_policy = ProtectorPolicy::new(
        decode_scope(record[offset])?,
        decode_presence(record[offset + 1])?,
    );
    Ok((stored_vault, stored_generation, stored_policy))
}

fn validate_record_binding(
    record: &[u8],
    expected_vault_id: VaultId,
    expected_generation: Option<KeyGeneration>,
    expected_policy: ProtectorPolicy,
) -> Result<(), ProtectorError> {
    let (stored_vault, stored_generation, stored_policy) = record_binding(record)?;
    if stored_vault != expected_vault_id
        || expected_generation.is_some_and(|generation| generation != stored_generation)
    {
        return Err(ProtectorError::OwnerMismatch);
    }
    if stored_policy != expected_policy {
        return Err(ProtectorError::PolicyMismatch);
    }
    Ok(())
}

fn decode_record(
    record: &[u8],
    expected_vault_id: VaultId,
    expected_generation: KeyGeneration,
    expected_policy: ProtectorPolicy,
) -> Result<OwnedKeyMaterial, ProtectorError> {
    validate_record_binding(
        record,
        expected_vault_id,
        Some(expected_generation),
        expected_policy,
    )?;
    let key_offset = RECORD_BYTES - KEY_MATERIAL_BYTES;
    let key: &[u8; KEY_MATERIAL_BYTES] = record[key_offset..]
        .try_into()
        .map_err(|_| ProtectorError::CorruptOrTampered)?;
    Ok(OwnedKeyMaterial::from_bytes(*key))
}

fn record_matches_vrk(record: &[u8], expected: &OwnedKeyMaterial) -> Result<bool, ProtectorError> {
    if record.len() != RECORD_BYTES {
        return Err(ProtectorError::CorruptOrTampered);
    }
    let key_offset = RECORD_BYTES - KEY_MATERIAL_BYTES;
    Ok(expected.with_bytes(|bytes| record[key_offset..] == bytes[..]))
}

const fn encode_scope(scope: AccessScope) -> u8 {
    match scope {
        AccessScope::AppExclusive => 1,
        AccessScope::SameUserAccount => 2,
        AccessScope::SameUserSession => 3,
    }
}

fn decode_scope(value: u8) -> Result<AccessScope, ProtectorError> {
    match value {
        1 => Ok(AccessScope::AppExclusive),
        2 => Ok(AccessScope::SameUserAccount),
        3 => Ok(AccessScope::SameUserSession),
        _ => Err(ProtectorError::CorruptOrTampered),
    }
}

const fn encode_presence(policy: UserPresencePolicy) -> u8 {
    match policy {
        UserPresencePolicy::NotRequired => 0,
        UserPresencePolicy::RequiredEachSafeEvidenceUnlock => 1,
    }
}

fn decode_presence(value: u8) -> Result<UserPresencePolicy, ProtectorError> {
    match value {
        0 => Ok(UserPresencePolicy::NotRequired),
        1 => Ok(UserPresencePolicy::RequiredEachSafeEvidenceUnlock),
        _ => Err(ProtectorError::CorruptOrTampered),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HELPER_ENVIRONMENT, KeyringHelperCommand, LinuxProtectorId, LinuxSecretServiceConfig,
        RECORD_MAGIC, RecordStore, decode_record, encode_record, record_matches_vrk,
        validate_linux_policy, validate_record_binding,
    };
    use crate::vault::{
        AccessScope, HardwareBacking, KeyGeneration, ProtectorError, SecretProtector,
        UserPresencePolicy, VAULT_ID_BYTES, VaultId,
    };
    use crate::vault_keys::OwnedKeyMaterial;
    use crate::vault_protector::ProtectorPolicy;
    use safeevidence_keyring_wire::{ProtectorId, SecretBytes};
    use zeroize::Zeroizing;

    fn vault(byte: u8) -> VaultId {
        VaultId::from_bytes([byte; VAULT_ID_BYTES])
    }

    fn generation(value: u64) -> KeyGeneration {
        KeyGeneration::new(value).expect("non-zero generation")
    }

    #[derive(Default)]
    struct Memory(Option<Vec<u8>>);

    impl RecordStore for Memory {
        fn ensure_unlocked(&mut self, _id: &ProtectorId) -> Result<(), ProtectorError> {
            Ok(())
        }
        fn read(&mut self, _id: &ProtectorId) -> Result<Option<SecretBytes>, ProtectorError> {
            Ok(self.0.clone().map(Zeroizing::new))
        }
        fn create(&mut self, _id: &ProtectorId, record: &[u8]) -> Result<(), ProtectorError> {
            self.0 = Some(record.to_vec());
            Ok(())
        }
        fn delete(&mut self, _id: &ProtectorId) -> Result<(), ProtectorError> {
            self.0 = None;
            Ok(())
        }
    }

    fn protector_with(store: Memory) -> super::LinuxSecretServiceProtector {
        super::LinuxSecretServiceProtector {
            config: LinuxSecretServiceConfig::new(LinuxProtectorId::from_bytes([1; 16])),
            policy: None,
            store: Box::new(store),
        }
    }

    fn protector() -> super::LinuxSecretServiceProtector {
        protector_with(Memory::default())
    }

    #[test]
    fn the_protector_stores_the_vrk_and_returns_exactly_those_bytes() {
        let mut protector = protector();
        let vrk = OwnedKeyMaterial::from_bytes([0x7a; 32]);
        assert_eq!(
            protector.protect_or_store_vrk(vault(1), generation(1), &vrk),
            Err(ProtectorError::UnsupportedPolicy),
            "nothing works before the policy is set"
        );
        protector
            .create_protector(
                AccessScope::SameUserSession,
                UserPresencePolicy::NotRequired,
            )
            .expect("baseline policy");
        protector
            .protect_or_store_vrk(vault(1), generation(1), &vrk)
            .expect("store");
        protector
            .protect_or_store_vrk(vault(1), generation(1), &vrk)
            .expect("same VRK");
        let unlocked = protector
            .unlock_vrk(vault(1), generation(1))
            .expect("unlock");
        assert!(unlocked.with_bytes(|bytes| *bytes == [0x7a; 32]));
    }

    #[test]
    fn a_stored_record_with_the_wrong_length_fails_closed() {
        let mut protector = protector_with(Memory(Some(vec![0; 5])));
        protector
            .create_protector(
                AccessScope::SameUserSession,
                UserPresencePolicy::NotRequired,
            )
            .expect("baseline policy");
        assert_eq!(
            protector.unlock_vrk(vault(1), generation(1)).map(|_| ()),
            Err(ProtectorError::CorruptOrTampered)
        );
    }

    #[test]
    fn the_helper_starts_by_absolute_path_with_a_minimal_environment() {
        assert_eq!(
            KeyringHelperCommand::new("relative/helper")
                .map(|_| ())
                .unwrap_err(),
            ProtectorError::Unavailable
        );
        assert_eq!(
            HELPER_ENVIRONMENT,
            ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "HOME"]
        );
    }

    #[test]
    fn baseline_policy_is_same_user_session_without_presence_or_hardware_claim() {
        assert!(
            validate_linux_policy(
                AccessScope::SameUserSession,
                UserPresencePolicy::NotRequired
            )
            .is_ok()
        );
        assert_eq!(
            validate_linux_policy(AccessScope::AppExclusive, UserPresencePolicy::NotRequired),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert_eq!(
            validate_linux_policy(
                AccessScope::SameUserAccount,
                UserPresencePolicy::NotRequired
            ),
            Err(ProtectorError::UnsupportedPolicy)
        );
        assert_eq!(
            validate_linux_policy(
                AccessScope::SameUserSession,
                UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
            ),
            Err(ProtectorError::UnsupportedPolicy)
        );

        let protector = protector();
        assert_eq!(
            protector.actual_access_scope(),
            AccessScope::SameUserSession
        );
        assert!(!protector.requires_user_presence());
        assert_eq!(protector.hardware_backed_state(), HardwareBacking::Unknown);
    }

    #[test]
    fn protected_record_binds_vault_generation_policy_and_vrk() {
        let vrk = OwnedKeyMaterial::from_bytes([0x5a; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserSession,
            UserPresencePolicy::NotRequired,
        );
        let record = encode_record(vault(0x11), generation(7), policy, &vrk);
        assert!(record.starts_with(RECORD_MAGIC));
        assert_eq!(
            validate_record_binding(&record, vault(0x11), Some(generation(7)), policy),
            Ok(())
        );
        assert!(record_matches_vrk(&record, &vrk).expect("well-formed record"));
        assert!(decode_record(&record, vault(0x11), generation(7), policy).is_ok());
        assert_eq!(
            validate_record_binding(&record, vault(0x12), Some(generation(7)), policy),
            Err(ProtectorError::OwnerMismatch)
        );
        assert_eq!(
            validate_record_binding(&record, vault(0x11), Some(generation(8)), policy),
            Err(ProtectorError::OwnerMismatch)
        );
    }

    #[test]
    fn malformed_or_policy_transplanted_records_fail_closed() {
        let vrk = OwnedKeyMaterial::from_bytes([0x33; 32]);
        let policy = ProtectorPolicy::new(
            AccessScope::SameUserSession,
            UserPresencePolicy::NotRequired,
        );
        let mut record = encode_record(vault(0x21), generation(3), policy, &vrk);
        record[0] ^= 1;
        assert_eq!(
            decode_record(&record, vault(0x21), generation(3), policy).map(|_| ()),
            Err(ProtectorError::CorruptOrTampered)
        );

        let clean = encode_record(vault(0x21), generation(3), policy, &vrk);
        let other_policy = ProtectorPolicy::new(
            AccessScope::SameUserSession,
            UserPresencePolicy::RequiredEachSafeEvidenceUnlock,
        );
        assert_eq!(
            validate_record_binding(&clean, vault(0x21), Some(generation(3)), other_policy),
            Err(ProtectorError::PolicyMismatch)
        );
    }
}
