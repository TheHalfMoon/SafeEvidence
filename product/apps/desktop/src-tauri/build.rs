fn main() {
    // Keep in sync with `generate_handler!` in src/main.rs; capabilities/default.json
    // grants exactly these commands to the main window.
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(&["ask_question"]));
    tauri_build::try_build(attributes).expect("failed to build the constrained Tauri manifest");
}
