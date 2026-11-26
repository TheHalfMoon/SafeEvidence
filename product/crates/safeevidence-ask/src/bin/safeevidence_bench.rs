//! CLI entry point for `SafeEvidenceBench` (`WP-20` / `TA-23`).
//!
//! Usage:
//!   `safeevidence_bench`               (writes canonical JSON packet to stdout)
//!   `safeevidence_bench --out <path>`  (writes canonical JSON packet to `<path>`)

use std::path::PathBuf;
use std::process::ExitCode;

use safeevidence_ask::bench_runner::{render_bench_packet_json, run_safeevidence_bench};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut out_path: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let Some(path) = args.next() else {
                    eprintln!("error: --out requires a file path");
                    return ExitCode::from(2);
                };
                out_path = Some(PathBuf::from(path));
            }
            other => {
                eprintln!("error: unsupported argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let packet = match run_safeevidence_bench() {
        Ok(packet) => packet,
        Err(error) => {
            eprintln!("error: SafeEvidenceBench failed: {error}");
            return ExitCode::from(1);
        }
    };
    let json = match render_bench_packet_json(&packet) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("error: JSON rendering failed: {error}");
            return ExitCode::from(1);
        }
    };

    if let Some(path) = out_path {
        if let Err(error) = std::fs::write(&path, json.as_bytes()) {
            eprintln!("error: could not write {}: {error}", path.display());
            return ExitCode::from(1);
        }
    } else {
        print!("{json}");
    }
    ExitCode::SUCCESS
}
