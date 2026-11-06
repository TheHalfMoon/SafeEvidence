//! The vault's protector against a real child process. This binary is also its own fake helper, chosen by
//! argument: a default test harness would print to stdout, which is the protocol stream.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use safeevidence_keyring_wire::{
    Backend, ProtectorId, Reply, SecretBytes, VERSION, WireError, encode_reply, read_frame, serve,
    write_frame,
};
use safeevidence_vault::vault::{
    AccessScope, KeyGeneration, ProtectorError, SecretProtector, UserPresencePolicy,
    VAULT_ID_BYTES, VaultId,
};
use safeevidence_vault::vault_keys::OwnedKeyMaterial;
use safeevidence_vault::vault_linux_secret_service::{
    KeyringHelperCommand, LinuxProtectorId, LinuxSecretServiceConfig, LinuxSecretServiceProtector,
};
use zeroize::Zeroizing;

#[derive(Default)]
struct Memory(HashMap<ProtectorId, Vec<u8>>);

impl Backend for Memory {
    fn ensure_unlocked(&mut self, _id: &ProtectorId) -> Result<(), WireError> {
        Ok(())
    }
    fn read(&mut self, id: &ProtectorId) -> Result<Option<SecretBytes>, WireError> {
        Ok(self.0.get(id).cloned().map(Zeroizing::new))
    }
    fn create(&mut self, id: &ProtectorId, record: &[u8]) -> Result<(), WireError> {
        self.0.insert(*id, record.to_vec());
        Ok(())
    }
    fn delete(&mut self, id: &ProtectorId) -> Result<(), WireError> {
        self.0.remove(id);
        Ok(())
    }
}

/// Answers every request with this, reading one frame first.
fn answer_once_with(frame: &[u8]) {
    let (mut stdin, mut stdout) = (std::io::stdin().lock(), std::io::stdout().lock());
    let _ = read_frame(&mut stdin);
    let _ = write_frame(&mut stdout, frame);
    std::thread::sleep(Duration::from_secs(30));
}

fn fake_helper(mode: &str) {
    match mode {
        "memory" => {
            let result = serve(
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
                &mut Memory::default(),
            );
            std::process::exit(i32::from(result.is_err()));
        }
        "exit" => std::process::exit(0),
        "exit-after-read" => {
            let _ = read_frame(&mut std::io::stdin().lock());
            std::process::exit(0);
        }
        "hang" => {
            let _ = read_frame(&mut std::io::stdin().lock());
            std::thread::sleep(Duration::from_secs(30));
        }
        "garbage" => answer_once_with(b"not a reply"),
        "future-version" => answer_once_with(&[VERSION + 1, 0]),
        "locked" => answer_once_with(&encode_reply(&Reply::Failed(WireError::Locked))),
        "denied" => answer_once_with(&encode_reply(&Reply::Failed(WireError::Denied))),
        "wrong-reply-kind" => answer_once_with(&encode_reply(&Reply::NoRecord)),
        "oversized" => {
            use std::io::Write as _;
            let _ = read_frame(&mut std::io::stdin().lock());
            let _ = std::io::stdout().write_all(&u32::MAX.to_be_bytes());
            let _ = std::io::stdout().flush();
            std::thread::sleep(Duration::from_secs(30));
        }
        "cut-short" => {
            use std::io::Write as _;
            let _ = read_frame(&mut std::io::stdin().lock());
            let _ = std::io::stdout().write_all(&[0, 0, 0, 9, 1]);
            let _ = std::io::stdout().flush();
        }
        marker if marker.starts_with("exit-once=") => {
            let path = &marker["exit-once=".len()..];
            if !std::path::Path::new(path).exists() {
                let _ = std::fs::write(path, b"ran");
                std::process::exit(0);
            }
            fake_helper("memory");
        }
        "env" => {
            let leaked = std::env::var_os("SE_TEST_MUST_NOT_REACH_HELPER").is_some()
                || std::env::var_os("PATH").is_some();
            let reply = if leaked {
                Reply::Failed(WireError::Denied)
            } else {
                Reply::Done
            };
            answer_once_with(&encode_reply(&reply));
        }
        other => panic!("unknown mode {other}"),
    }
}

fn command(mode: &str) -> KeyringHelperCommand {
    KeyringHelperCommand::new(std::env::current_exe().expect("test binary"))
        .expect("absolute path")
        .with_reply_timeout(Duration::from_secs(10))
        .with_test_argument("--fake-helper")
        .with_test_argument(mode)
}

fn protector(helper: KeyringHelperCommand) -> LinuxSecretServiceProtector {
    LinuxSecretServiceProtector::new(
        LinuxSecretServiceConfig::new(LinuxProtectorId::from_bytes([9; 16])),
        helper,
    )
}

fn set_policy(protector: &mut LinuxSecretServiceProtector) -> Result<(), ProtectorError> {
    protector.create_protector(
        AccessScope::SameUserSession,
        UserPresencePolicy::NotRequired,
    )
}

fn vault(byte: u8) -> VaultId {
    VaultId::from_bytes([byte; VAULT_ID_BYTES])
}

fn generation(value: u64) -> KeyGeneration {
    KeyGeneration::new(value).expect("non-zero")
}

fn key(byte: u8) -> OwnedKeyMaterial {
    OwnedKeyMaterial::from_bytes([byte; 32])
}

fn records_cross_the_process_boundary_with_their_bindings() {
    let mut protector = protector(command("memory"));
    set_policy(&mut protector).expect("policy");
    assert_eq!(
        protector.unlock_vrk(vault(1), generation(1)).map(|_| ()),
        Err(ProtectorError::ItemMissing)
    );
    protector
        .protect_or_store_vrk(vault(1), generation(1), &key(1))
        .expect("store");
    protector
        .protect_or_store_vrk(vault(1), generation(1), &key(1))
        .expect("same key matches");
    assert_eq!(
        protector.protect_or_store_vrk(vault(1), generation(1), &key(2)),
        Err(ProtectorError::CorruptOrTampered)
    );
    protector
        .unlock_vrk(vault(1), generation(1))
        .expect("unlock");
    assert_eq!(
        protector.unlock_vrk(vault(2), generation(1)).map(|_| ()),
        Err(ProtectorError::OwnerMismatch)
    );
    assert_eq!(
        protector.unlock_vrk(vault(1), generation(2)).map(|_| ()),
        Err(ProtectorError::OwnerMismatch)
    );
    assert_eq!(
        protector.remove_protector(vault(2)),
        Err(ProtectorError::OwnerMismatch)
    );
    protector.remove_protector(vault(1)).expect("remove");
    set_policy(&mut protector).expect("policy again");
    assert_eq!(
        protector.unlock_vrk(vault(1), generation(1)).map(|_| ()),
        Err(ProtectorError::ItemMissing)
    );
}

fn a_missing_helper_is_unavailable() {
    let path = std::env::temp_dir().join("se-no-such-keyring-helper");
    let mut protector = protector(KeyringHelperCommand::new(path).expect("absolute"));
    assert_eq!(set_policy(&mut protector), Err(ProtectorError::Unavailable));
}

fn helper_failures_fail_closed() {
    for (mode, expected) in [
        ("exit", ProtectorError::Unavailable),
        ("exit-after-read", ProtectorError::Unavailable),
        ("cut-short", ProtectorError::Unavailable),
        ("oversized", ProtectorError::Unavailable),
        ("garbage", ProtectorError::CorruptOrTampered),
        ("future-version", ProtectorError::CorruptOrTampered),
        ("wrong-reply-kind", ProtectorError::CorruptOrTampered),
        ("locked", ProtectorError::Locked),
        ("denied", ProtectorError::Denied),
    ] {
        let mut protector = protector(command(mode));
        assert_eq!(set_policy(&mut protector), Err(expected), "{mode}");
        assert_eq!(
            protector.unlock_vrk(vault(1), generation(1)).map(|_| ()),
            Err(ProtectorError::UnsupportedPolicy),
            "{mode}: a failed setup sets no policy"
        );
    }
}

fn a_helper_that_stops_answering_times_out_and_is_killed() {
    let mut protector = protector(command("hang").with_reply_timeout(Duration::from_millis(300)));
    let started = Instant::now();
    assert_eq!(set_policy(&mut protector), Err(ProtectorError::Unavailable));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
}

fn a_new_call_after_a_failure_starts_a_new_helper() {
    // The helper exits on its first run. Each spawn is a new process, so the first call fails and only a
    // real respawn can make the second succeed. The fake keeps its first-run state in this file.
    let marker = std::env::temp_dir().join(format!("se-helper-once-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let mode = format!("exit-once={}", marker.display());
    let mut protector = protector(command(&mode));
    assert_eq!(set_policy(&mut protector), Err(ProtectorError::Unavailable));
    set_policy(&mut protector).expect("the next call starts a new helper");
    protector
        .protect_or_store_vrk(vault(1), generation(1), &key(1))
        .expect("store");
    protector
        .unlock_vrk(vault(1), generation(1))
        .expect("the session persists across calls");
    let _ = std::fs::remove_file(&marker);
}

fn the_helper_inherits_only_the_allowed_environment() {
    let mut protector = protector(command("env"));
    assert_eq!(
        set_policy(&mut protector),
        Ok(()),
        "PATH and other variables must not reach it"
    );
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.get(1).map(String::as_str) == Some("--fake-helper") {
        fake_helper(&arguments[2]);
        return;
    }
    let tests: [(&str, fn()); 6] = [
        (
            "records_cross_the_process_boundary_with_their_bindings",
            records_cross_the_process_boundary_with_their_bindings,
        ),
        (
            "a_missing_helper_is_unavailable",
            a_missing_helper_is_unavailable,
        ),
        ("helper_failures_fail_closed", helper_failures_fail_closed),
        (
            "a_helper_that_stops_answering_times_out_and_is_killed",
            a_helper_that_stops_answering_times_out_and_is_killed,
        ),
        (
            "a_new_call_after_a_failure_starts_a_new_helper",
            a_new_call_after_a_failure_starts_a_new_helper,
        ),
        (
            "the_helper_inherits_only_the_allowed_environment",
            the_helper_inherits_only_the_allowed_environment,
        ),
    ];
    for (name, test) in tests {
        println!("test {name} ...");
        test();
        println!("test {name} ... ok");
    }
    println!("test result: ok. {} passed; 0 failed", tests.len());
}
