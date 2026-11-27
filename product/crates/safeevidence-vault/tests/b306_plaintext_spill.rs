#![forbid(unsafe_code)]

use hkdf::Hkdf;
use rusqlite::{Connection, OpenFlags, params};
use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;
use safeevidence_vault::vault_sqlcipher::{
    EXPECTED_OPENSSL_RUNTIME_VERSION, EXPECTED_SQLCIPHER_CRYPTO_PROVIDER,
    EXPECTED_SQLCIPHER_RUNTIME_VERSION, EXPECTED_SQLITE_RUNTIME_VERSION, open_sqlcipher_database,
};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const SEMANTIC_MARKER: &str = "SAFEEVIDENCE_B306_SEMANTIC_MARKER_8E4D9A7C";
const LOGICAL_ID: &str = "urn:safeevidence:b306:logical-id:7f34d6c2-9a41";
const TEMP_STORE_MEMORY: i64 = 2;

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn identity() -> VaultLeaseIdentity {
    VaultLeaseIdentity::new(
        VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
        KeyGeneration::new(7).expect("test generation is non-zero"),
    )
}

fn context() -> KeyDerivationContext {
    let identity = identity();
    KeyDerivationContext::new(
        identity.vault_id(),
        identity.key_generation(),
        KeyPurpose::StructuredStore,
    )
}

fn vrk_bytes() -> [u8; KEY_MATERIAL_BYTES] {
    [0x52; KEY_MATERIAL_BYTES]
}

fn structured_key_bytes() -> [u8; KEY_MATERIAL_BYTES] {
    let context = context();
    let salt = context.hkdf_salt();
    let info = context.hkdf_info();
    let vrk = vrk_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), vrk.as_slice());
    let mut output = [0_u8; KEY_MATERIAL_BYTES];
    hkdf.expand(info.as_slice(), &mut output)
        .expect("32-byte HKDF-SHA-256 output is within the RFC 5869 expansion limit");
    output
}

fn raw_key_pragma(key: &[u8; KEY_MATERIAL_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut sql = String::with_capacity(18 + (KEY_MATERIAL_BYTES * 2));
    sql.push_str("PRAGMA key = \"x'");
    for byte in key {
        sql.push(char::from(HEX[usize::from(byte >> 4)]));
        sql.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    sql.push_str("'\";");
    sql
}

fn provider_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

fn fixture_path() -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "safeevidence-b306-spill-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("B306 fixture directory must be created");
    directory.join("artifact.db")
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}

fn cleanup_fixture(path: &Path) {
    for suffix in ["-wal", "-shm", "-journal"] {
        let _ = fs::remove_file(sidecar_path(path, suffix));
    }
    let _ = fs::remove_file(path);
    if let Some(parent) = path.parent() {
        let _ = fs::remove_dir(parent);
    }
}

fn assert_public_filename_clean(path: &Path) {
    let rendered = path.to_string_lossy();
    assert!(
        !rendered.contains(SEMANTIC_MARKER),
        "semantic marker must not appear in public filename: {rendered}"
    );
    assert!(
        !rendered.contains(LOGICAL_ID),
        "logical ID must not appear in public filename: {rendered}"
    );
}

fn assert_sensitive_bytes_absent(path: &Path, surface: &str) {
    let bytes = fs::read(path).unwrap_or_else(|error| {
        panic!(
            "B306 {surface} bytes must be readable from {}: {error}",
            path.display()
        )
    });
    assert!(
        !bytes.is_empty(),
        "B306 {surface} must contain genuine file-backed evidence"
    );

    for (label, needle) in [
        ("semantic marker", SEMANTIC_MARKER.as_bytes()),
        ("logical ID", LOGICAL_ID.as_bytes()),
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "B306 {surface} leaked {label} plaintext"
        );
    }
}

fn keyed_qualification_connection(path: &Path) -> Connection {
    cleanup_fixture(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("B306 fixture directory must exist");
    }

    let connection = Connection::open_with_flags(path, provider_open_flags())
        .expect("reviewed SQLCipher provider must open the B306 fixture");
    let structured_key = structured_key_bytes();
    connection
        .execute_batch(&raw_key_pragma(&structured_key))
        .expect("reviewed SQLCipher raw key operation must succeed");

    let sqlcipher_version = connection
        .query_row("PRAGMA cipher_version;", [], |row| row.get::<_, String>(0))
        .expect("SQLCipher runtime identity must be queryable");
    assert_eq!(sqlcipher_version, EXPECTED_SQLCIPHER_RUNTIME_VERSION);

    let sqlite_version = connection
        .query_row("SELECT sqlite_version();", [], |row| {
            row.get::<_, String>(0)
        })
        .expect("SQLite runtime identity must be queryable");
    assert_eq!(sqlite_version, EXPECTED_SQLITE_RUNTIME_VERSION);

    let cipher_status = connection
        .query_row("PRAGMA cipher_status;", [], |row| row.get::<_, String>(0))
        .expect("SQLCipher encryption status must be queryable");
    assert_eq!(cipher_status, "1");

    let provider = connection
        .query_row("PRAGMA cipher_provider;", [], |row| row.get::<_, String>(0))
        .expect("SQLCipher crypto provider must be queryable");
    assert_eq!(provider, EXPECTED_SQLCIPHER_CRYPTO_PROVIDER);

    let provider_version = connection
        .query_row("PRAGMA cipher_provider_version;", [], |row| {
            row.get::<_, String>(0)
        })
        .expect("SQLCipher crypto provider version must be queryable");
    assert_eq!(provider_version, EXPECTED_OPENSSL_RUNTIME_VERSION);

    #[cfg(target_os = "android")]
    let expected_temp_store_compile_option = "TEMP_STORE=3";
    #[cfg(not(target_os = "android"))]
    let expected_temp_store_compile_option = "TEMP_STORE=2";

    let compile_posture = connection
        .query_row(
            "SELECT sqlite_compileoption_used(?1);",
            [expected_temp_store_compile_option],
            |row| row.get::<_, i64>(0),
        )
        .expect("reviewed temp-store compile posture must be queryable");
    assert_eq!(compile_posture, 1);

    connection
        .execute_batch("PRAGMA temp_store = MEMORY;")
        .expect("B306 must retain memory-only temporary storage");
    let temp_store = connection
        .query_row("PRAGMA temp_store;", [], |row| row.get::<_, i64>(0))
        .expect("B306 temp-store posture must remain queryable");
    assert_eq!(temp_store, TEMP_STORE_MEMORY);

    connection
}

#[test]
fn b306_plaintext_spill_surfaces_remain_opaque_under_qualified_sqlcipher_posture() {
    let path = fixture_path();
    let wal_path = sidecar_path(&path, "-wal");
    let shm_path = sidecar_path(&path, "-shm");
    let journal_path = sidecar_path(&path, "-journal");

    for public_path in [&path, &wal_path, &shm_path, &journal_path] {
        assert_public_filename_clean(public_path);
    }

    let connection = keyed_qualification_connection(&path);

    let wal_mode = connection
        .query_row("PRAGMA journal_mode = WAL;", [], |row| {
            row.get::<_, String>(0)
        })
        .expect("reviewed SQLCipher provider must enter WAL mode");
    assert_eq!(wal_mode, "wal");
    connection
        .execute_batch("PRAGMA wal_autocheckpoint = 0;")
        .expect("B306 WAL evidence must not be removed by auto-checkpointing");
    connection
        .execute_batch(
            "CREATE TABLE spill_probe (semantic_marker TEXT NOT NULL, logical_id TEXT NOT NULL, sort_key TEXT NOT NULL);",
        )
        .expect("B306 spill probe table must be created");
    connection
        .execute(
            "INSERT INTO spill_probe (semantic_marker, logical_id, sort_key) VALUES (?1, ?2, ?3);",
            params![SEMANTIC_MARKER, LOGICAL_ID, "stable"],
        )
        .expect("B306 semantic fixture row must commit to WAL");

    let observed = connection
        .query_row(
            "SELECT semantic_marker, logical_id FROM spill_probe WHERE logical_id = ?1;",
            [LOGICAL_ID],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .expect("B306 semantic fixture row must round-trip before byte inspection");
    assert_eq!(observed.0, SEMANTIC_MARKER);
    assert_eq!(observed.1, LOGICAL_ID);

    assert_sensitive_bytes_absent(&wal_path, "WAL");
    if shm_path.exists() {
        assert_sensitive_bytes_absent(&shm_path, "shared-memory sidecar");
    }

    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("B306 WAL checkpoint must publish encrypted pages into the main database");
    assert_sensitive_bytes_absent(&path, "database");

    let rollback_mode = connection
        .query_row("PRAGMA journal_mode = DELETE;", [], |row| {
            row.get::<_, String>(0)
        })
        .expect("reviewed SQLCipher provider must enter rollback-journal mode");
    assert_eq!(rollback_mode, "delete");
    connection
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("B306 rollback-journal transaction must begin");
    connection
        .execute(
            "UPDATE spill_probe SET sort_key = ?1 WHERE logical_id = ?2;",
            params!["mutated", LOGICAL_ID],
        )
        .expect("B306 rollback-journal transaction must write a protected page");
    assert_sensitive_bytes_absent(&journal_path, "rollback journal");
    connection
        .execute_batch("ROLLBACK;")
        .expect("B306 rollback-journal fixture must return to the verified prior state");

    connection
        .execute_batch(
            "CREATE TEMP TABLE temp_spill_probe (semantic_marker TEXT NOT NULL, logical_id TEXT NOT NULL, sort_key INTEGER NOT NULL);",
        )
        .expect("B306 sensitive temp table must be created in memory");
    for sort_key in 0..256_i64 {
        connection
            .execute(
                "INSERT INTO temp_spill_probe (semantic_marker, logical_id, sort_key) VALUES (?1, ?2, ?3);",
                params![SEMANTIC_MARKER, LOGICAL_ID, sort_key],
            )
            .expect("B306 sensitive temp row must remain memory-backed");
    }
    let sorted_probe = connection
        .query_row(
            "SELECT semantic_marker, logical_id FROM temp_spill_probe ORDER BY sort_key DESC LIMIT 1;",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .expect("B306 sensitive temp sort must execute under memory-only posture");
    assert_eq!(sorted_probe.0, SEMANTIC_MARKER);
    assert_eq!(sorted_probe.1, LOGICAL_ID);

    let temp_store = connection
        .query_row("PRAGMA temp_store;", [], |row| row.get::<_, i64>(0))
        .expect("B306 temp-store posture must remain queryable after sensitive temp work");
    assert_eq!(temp_store, TEMP_STORE_MEMORY);
    let temp_journal_mode = connection
        .query_row("PRAGMA temp.journal_mode;", [], |row| {
            row.get::<_, String>(0)
        })
        .expect("B306 temp journal mode must be queryable");
    assert_eq!(temp_journal_mode, "memory");

    let mut database_list = connection
        .prepare("PRAGMA database_list;")
        .expect("B306 database-list evidence must be queryable");
    let mut rows = database_list
        .query([])
        .expect("B306 database-list rows must be readable");
    let mut main_filename = None;
    let mut temp_filename = None;
    while let Some(row) = rows
        .next()
        .expect("B306 database-list iteration must succeed")
    {
        let name = row
            .get::<_, String>(1)
            .expect("B306 database-list schema name must be text");
        let filename = row
            .get::<_, String>(2)
            .expect("B306 database-list filename must be text");
        match name.as_str() {
            "main" => main_filename = Some(filename),
            "temp" => temp_filename = Some(filename),
            _ => {}
        }
    }
    drop(rows);
    drop(database_list);

    let main_filename = main_filename.expect("B306 main database filename must be reported");
    assert_public_filename_clean(Path::new(&main_filename));
    assert_eq!(
        temp_filename.as_deref(),
        Some(""),
        "B306 memory-only temp schema must have no file-backed public filename"
    );

    drop(connection);

    let lease = VaultLease::new(identity());
    let vrk = OwnedKeyMaterial::from_bytes(vrk_bytes());
    let handle = open_sqlcipher_database(&path, lease.keyed_handle_lease(), context(), &vrk)
        .expect("production SQLCipher path must reopen the exact B306 qualified fixture");
    assert_eq!(handle.verify_integrity(), Ok(()));

    drop(handle);
    cleanup_fixture(&path);
}
