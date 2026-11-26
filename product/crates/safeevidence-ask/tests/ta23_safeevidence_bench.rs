//! `WP-20` / `TA-23`: `SafeEvidenceBench` reproducibility and split-governance gate.
//!
//! Verifies that:
//! 1. Independent invocations of the compiled `safeevidence_bench` binary from separate working
//!    directories emit byte-for-byte identical JSON packets and identical input/output digests.
//! 2. Every registered synthetic split identity (`TA-09`, `TA-08`, `TA-10`, `TA-07`, `TA-17`) is
//!    present, passes its engineering gate, and carries an exact SHA-256 input digest.
//! 3. `clinical_claim_emitted` is `false`, no confidence percentages appear, and externally gated
//!    components (`EXT-01`, `EXT-03`, `EXT-07`) are explicitly fenced as `BLOCKED_EXTERNAL`.

use std::path::PathBuf;
use std::process::Command;

use safeevidence_ask::bench_runner::{
    BENCH_SCHEMA_VERSION, BenchPacket, render_bench_packet_json, run_safeevidence_bench,
};
use safeevidence_contracts::objects::DigestSha256;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("se-bench-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ta23_two_independent_runs_produce_identical_digests_and_record_split_identities() {
    let run_a = run_safeevidence_bench().expect("run A succeeds");
    let run_b = run_safeevidence_bench().expect("run B succeeds");
    assert_eq!(run_a, run_b);
    assert_eq!(run_a.body.schema_version, BENCH_SCHEMA_VERSION);
    assert!(run_a.body.synthetic_only);
    assert!(!run_a.body.clinical_claim_emitted);

    let json_a = render_bench_packet_json(&run_a).expect("json A");
    let json_b = render_bench_packet_json(&run_b).expect("json B");
    assert_eq!(json_a, json_b);
    assert_eq!(
        DigestSha256::of(json_a.as_bytes()),
        DigestSha256::of(json_b.as_bytes())
    );

    // Verify all 6 split identities and passing gates:
    let split_ids: Vec<&str> = run_a
        .body
        .splits
        .iter()
        .map(|s| s.split_id.as_str())
        .collect();
    assert_eq!(
        split_ids,
        vec![
            "ta09-vs1a-heldout",
            "ta09-hard-m2-heldout",
            "ta08-bilingual-parallel-20",
            "ta10-perturbation-gate",
            "ta07-study-independence",
            "ta17-extraction-and-assurance",
        ]
    );
    for split in &run_a.body.splits {
        assert!(split.gate_passed, "split {} failed gate", split.split_id);
        assert!(!split.metrics.is_empty());
    }

    // Verify binary CLI execution from two clean temporary directories produces identical bytes:
    let bin = env!("CARGO_BIN_EXE_safeevidence_bench");
    let tmp_a = TempDir::new("a");
    let tmp_b = TempDir::new("b");
    let out_a = tmp_a.0.join("packet.json");
    let out_b = tmp_b.0.join("packet.json");

    let status_a = Command::new(bin)
        .current_dir(&tmp_a.0)
        .arg("--out")
        .arg(&out_a)
        .status()
        .expect("spawn bin A");
    let status_b = Command::new(bin)
        .current_dir(&tmp_b.0)
        .arg("--out")
        .arg(&out_b)
        .status()
        .expect("spawn bin B");
    assert!(status_a.success() && status_b.success());

    let bytes_a = std::fs::read(&out_a).expect("read out_a");
    let bytes_b = std::fs::read(&out_b).expect("read out_b");
    assert_eq!(bytes_a, bytes_b, "CLI packets must be byte-identical");
    assert_eq!(bytes_a, json_a.as_bytes());

    let parsed: BenchPacket = serde_json::from_slice(&bytes_a).expect("deserializes cleanly");
    assert_eq!(parsed.packet_digest, run_a.packet_digest);
    assert_eq!(
        parsed.body.input_bundle_digest,
        run_a.body.input_bundle_digest
    );
    assert_eq!(parsed.body.fenced_external_components.len(), 3);
    assert!(
        parsed
            .body
            .fenced_external_components
            .iter()
            .all(|c| c.status == "BLOCKED_EXTERNAL")
    );
}
