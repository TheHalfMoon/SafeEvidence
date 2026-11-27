//! Replaces the donor's media-journal kill test, whose subject is outside this slice.
//!
//! A real OS kill strikes a child committing to encrypted SQLCipher in each journal
//! mode. Acknowledged commits must survive; the database must reopen and pass integrity.
//! Kills land just after each acknowledged commit count, at no finer point. Scope: the
//! storage engine with `synchronous = FULL`, set by this test. It does not use the vault
//! open API, its connection settings or its lease path, and does not test power loss, so
//! it is only part of the P00 durability campaign (TA-05).

use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const COMMITS: u64 = 12;
const POLL_DEADLINE: Duration = Duration::from_secs(120);
const KEY_PRAGMA: &str =
    "PRAGMA key = \"x'4242424242424242424242424242424242424242424242424242424242424242'\"";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("se-kill-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).expect("temp root");
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open(path: &Path, journal_mode: &str) -> Connection {
    let connection = Connection::open(path).expect("open database");
    connection.execute_batch(KEY_PRAGMA).expect("apply key");
    let actual: String = connection
        .query_row(
            &format!("PRAGMA journal_mode = {journal_mode}"),
            [],
            |row| row.get(0),
        )
        .expect("journal mode");
    assert_eq!(
        actual.to_uppercase(),
        journal_mode,
        "journal mode not applied"
    );
    connection
        .execute_batch("PRAGMA synchronous = FULL")
        .expect("synchronous");
    connection
}

/// Child entry, spawned by the matrix below; ignored in normal runs.
#[test]
#[ignore = "spawned by kill_at_every_commit_point with SAFEEVIDENCE_KILL_CHILD=1"]
fn kill_writer_entry() {
    if std::env::var("SAFEEVIDENCE_KILL_CHILD").as_deref() != Ok("1") {
        return;
    }
    let root = PathBuf::from(std::env::var("SAFEEVIDENCE_KILL_ROOT").expect("root"));
    let mode = std::env::var("SAFEEVIDENCE_KILL_MODE").expect("mode");
    let connection = open(&root.join("vault.db"), &mode);
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS answers (id INTEGER PRIMARY KEY, body TEXT NOT NULL)",
        )
        .expect("schema");
    for index in 0..u64::MAX {
        connection
            .execute(
                "INSERT INTO answers (id, body) VALUES (?1, ?2)",
                rusqlite::params![index as i64, "synthetic-committed-row".repeat(40)],
            )
            .expect("commit");
        // Acknowledge only after the commit returned, then atomically publish it.
        let staged = root.join("ack.tmp");
        fs::write(&staged, (index + 1).to_string()).expect("stage ack");
        fs::rename(&staged, root.join("ack")).expect("publish ack");
    }
}

fn spawn_writer(root: &Path, mode: &str) -> Child {
    Command::new(std::env::current_exe().expect("test binary"))
        .args(["kill_writer_entry", "--exact", "--nocapture", "--ignored"])
        .env("SAFEEVIDENCE_KILL_CHILD", "1")
        .env("SAFEEVIDENCE_KILL_ROOT", root)
        .env("SAFEEVIDENCE_KILL_MODE", mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn writer")
}

/// A writer that already exited would make the kill meaningless, so refuse it.
fn kill_running(child: &mut Child) {
    assert!(
        child.try_wait().expect("child status").is_none(),
        "writer exited before the kill"
    );
    child.kill().expect("kill lands");
    let _ = child.wait();
}

fn acknowledged(root: &Path) -> u64 {
    fs::read_to_string(root.join("ack"))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

fn kill_after(mode: &str, kill_at: u64) {
    let root = TempRoot::new();
    let mut child = spawn_writer(&root.0, mode);
    let deadline = Instant::now() + POLL_DEADLINE;
    while acknowledged(&root.0) < kill_at {
        assert!(
            Instant::now() < deadline,
            "{mode} writer stalled at {kill_at}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    kill_running(&mut child);
    let acked = acknowledged(&root.0);

    let connection = open(&root.0.join("vault.db"), mode);
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity check runs");
    assert_eq!(integrity, "ok", "{mode} kill at {kill_at}");
    let (rows, highest): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(id), -1) FROM answers",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("rows readable");
    assert!(
        rows as u64 >= acked,
        "{mode}: lost acknowledged commit: {rows} < {acked}"
    );
    assert_eq!(highest + 1, rows, "{mode}: gap in committed rows");
    assert!(
        rows as u64 <= acked + 1,
        "{mode}: more than one unacknowledged commit"
    );
}

#[test]
fn kill_at_every_commit_point() {
    for mode in ["WAL", "DELETE"] {
        for kill_at in 1..=COMMITS {
            kill_after(mode, kill_at);
        }
    }
}

#[test]
fn wrong_key_cannot_read_after_kill() {
    let root = TempRoot::new();
    let mut child = spawn_writer(&root.0, "DELETE");
    let deadline = Instant::now() + POLL_DEADLINE;
    while acknowledged(&root.0) < 2 {
        assert!(Instant::now() < deadline, "writer stalled");
        std::thread::sleep(Duration::from_millis(1));
    }
    kill_running(&mut child);
    let connection = Connection::open(root.0.join("vault.db")).expect("open");
    connection
        .execute_batch(
            "PRAGMA key = \"x'4343434343434343434343434343434343434343434343434343434343434343'\"",
        )
        .expect("apply wrong key");
    assert!(
        connection
            .query_row("SELECT COUNT(*) FROM answers", [], |row| row
                .get::<_, i64>(0))
            .is_err()
    );
    let bytes = fs::read(root.0.join("vault.db")).expect("database bytes");
    assert!(
        !bytes
            .windows(23)
            .any(|window| window == b"synthetic-committed-row")
    );
}
