//! Plaintext residue in the real keyed store's directory, while it is live and after it closes.
//! This is part of `TA-05`'s residue clause, not a pass of it: the kill, disk-full and restore clauses
//! and OS-level surfaces are outside this test.

use std::path::{Path, PathBuf};

use safeevidence_ask::{ask, load_corpus};
use safeevidence_contracts::objects::DigestSha256;
use safeevidence_privacy_probes::scan_for_plaintext;
use safeevidence_proofstore::ProofStore;
use safeevidence_vault::vault::{KeyGeneration, VAULT_ID_BYTES, VaultId, VaultLeaseIdentity};
use safeevidence_vault::vault_keys::{
    KEY_MATERIAL_BYTES, KeyDerivationContext, KeyPurpose, OwnedKeyMaterial,
};
use safeevidence_vault::vault_lease::VaultLease;

const FIXTURE: &[u8] = include_bytes!("../../../crates/safeevidence-ask/fixtures/vs1a_corpus.json");
const QUESTION: &str = "Does veltrixamine help adults with glimmer syndrome?";

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("se-store-residue-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn file_names(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect()
}

/// Commits one answer and its sources, returning the store and every plaintext it must not leak.
fn committed_store(dir: &Path, lease: &VaultLease) -> (ProofStore, Vec<Vec<u8>>) {
    let identity = VaultLeaseIdentity::new(
        VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
        KeyGeneration::new(7).expect("generation"),
    );
    let context = KeyDerivationContext::new(
        identity.vault_id(),
        identity.key_generation(),
        KeyPurpose::StructuredStore,
    );
    let mut store = ProofStore::open(
        dir.join("vault.db"),
        lease.keyed_handle_lease(),
        context,
        &OwnedKeyMaterial::from_bytes([0x52; KEY_MATERIAL_BYTES]),
    )
    .expect("store opens");
    let corpus = load_corpus(FIXTURE, &DigestSha256::of(FIXTURE)).expect("fixture");
    store.advance_epoch(corpus.validity_epoch).expect("epoch");
    store
        .set_rights_grant(&corpus.rights_grant_version)
        .expect("rights");
    let mut markers = Vec::new();
    for document in &corpus.documents {
        store
            .put_source(&document.doc_id, document.text.as_bytes())
            .expect("source");
        markers.push(document.text.as_bytes().to_vec());
        markers.push(document.finding.as_bytes().to_vec());
    }
    let result = ask(QUESTION, &corpus);
    let brief = result.brief.expect("brief");
    let manifest = result.manifest.expect("manifest");
    store.commit(&manifest, brief.as_bytes()).expect("commit");
    markers.push(brief.into_bytes());
    markers.push(manifest.proof_id.into_bytes());
    markers.push(corpus.rights_grant_version.into_bytes());
    (store, markers)
}

fn scan(dir: &Path, markers: &[Vec<u8>]) -> safeevidence_privacy_probes::ResidueScan {
    let markers: Vec<&[u8]> = markers.iter().map(Vec::as_slice).collect();
    scan_for_plaintext(dir, &markers).expect("scan")
}

#[test]
fn no_plaintext_in_the_store_directory_while_live_or_after_close() {
    let dir = TempDir::new("live");
    let lease = VaultLease::new(VaultLeaseIdentity::new(
        VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
        KeyGeneration::new(7).expect("generation"),
    ));
    let (store, markers) = committed_store(&dir.0, &lease);
    assert!(markers.len() >= 5);

    let live = scan(&dir.0, &markers);
    let names = file_names(&live.files_scanned);
    assert!(names.iter().any(|name| name == "vault.db"), "{names:?}");
    assert!(
        names.iter().any(|name| name == "vault.db-wal"),
        "scanned while the WAL is live: {names:?}"
    );
    assert_eq!(live.hits, []);

    drop(store);
    let closed = scan(&dir.0, &markers);
    assert!(!closed.files_scanned.is_empty());
    assert_eq!(closed.hits, []);
}

#[test]
fn the_scan_would_find_this_plaintext_if_it_were_there() {
    let dir = TempDir::new("control");
    let lease = VaultLease::new(VaultLeaseIdentity::new(
        VaultId::from_bytes([0x41; VAULT_ID_BYTES]),
        KeyGeneration::new(7).expect("generation"),
    ));
    let (store, markers) = committed_store(&dir.0, &lease);
    let planted = dir.0.join("vault.db-journal");
    std::fs::write(&planted, &markers[0]).expect("plant");
    let found = scan(&dir.0, &markers);
    // A finding sits inside its source text, so the planted file can match more than one marker.
    assert!(found.hits.iter().any(|hit| hit.marker_index == 0));
    assert!(found.hits.iter().all(|hit| hit.path == planted));
    drop(store);
}
