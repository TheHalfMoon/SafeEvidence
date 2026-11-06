//! Invoke boundary tests use the production handler and generated capabilities, in the dev context
//! `cargo test` builds, which also admits `127.0.0.1:1420`. MockRuntime does not establish native
//! WebView privacy or OS isolation.

use tauri::Manager;
use tauri::test::{MockRuntime, get_ipc_response, mock_builder};
use tauri::webview::InvokeRequest;

fn test_app(data_dir: &std::path::Path) -> tauri::App<MockRuntime> {
    let app = super::presentation_builder(mock_builder())
        .build(tauri::generate_context!())
        .expect("build production permission context");
    app.state::<super::ask_command::AskState>()
        .set_data_dir(data_dir.to_path_buf());
    app
}

fn request(command: &str, origin: &str, body: serde_json::Value) -> InvokeRequest {
    InvokeRequest {
        cmd: command.to_owned(),
        callback: tauri::ipc::CallbackFn(0),
        error: tauri::ipc::CallbackFn(1),
        url: origin.parse().expect("test origin"),
        body: tauri::ipc::InvokeBody::Json(body),
        headers: Default::default(),
        invoke_key: tauri::test::INVOKE_KEY.to_owned(),
    }
}

fn local_origin() -> &'static str {
    if cfg!(any(windows, target_os = "android")) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    }
}

fn question() -> serde_json::Value {
    serde_json::json!({ "question": "Does veltrixamine help adults with glimmer syndrome?" })
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("se-perm-{}-{label}", std::process::id()));
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
fn the_main_local_window_can_ask() {
    let dir = TempDir::new("main");
    let app = test_app(&dir.0);
    let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("main mock window");
    let response = get_ipc_response(&window, request("ask_question", local_origin(), question()))
        .expect("admitted command")
        .deserialize::<serde_json::Value>()
        .expect("json");
    assert_eq!(response["outcome"], "ANSWER_WITH_CAUTION");
    assert!(response["brief"].is_string());
    app.state::<super::ask_command::AskState>().close();
}

#[test]
fn a_too_long_question_gets_a_refusal() {
    let dir = TempDir::new("long");
    let app = test_app(&dir.0);
    let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("main mock window");
    let body = serde_json::json!({ "question": "x".repeat(1025) });
    let response = get_ipc_response(&window, request("ask_question", local_origin(), body))
        .expect("admitted command")
        .deserialize::<serde_json::Value>()
        .expect("json");
    assert_eq!(response["outcome"], "ABSTAIN");
    assert!(response["brief"].is_null());
}

#[test]
fn remote_origins_cannot_invoke_the_admitted_command() {
    let dir = TempDir::new("remote");
    let app = test_app(&dir.0);
    let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("main mock window");
    for origin in [
        "https://example.invalid",
        "http://tauri.localhost.example.invalid",
    ] {
        assert!(get_ipc_response(&window, request("ask_question", origin, question())).is_err());
    }
}

#[test]
fn an_ungranted_window_cannot_ask() {
    let dir = TempDir::new("ungranted");
    let app = test_app(&dir.0);
    let window = tauri::WebviewWindowBuilder::new(&app, "ungranted", Default::default())
        .build()
        .expect("ungranted mock window");
    assert!(
        get_ipc_response(&window, request("ask_question", local_origin(), question())).is_err()
    );
}

#[test]
fn generic_privilege_and_plugin_commands_are_refused() {
    let dir = TempDir::new("generic");
    let app = test_app(&dir.0);
    let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("main mock window");
    for command in [
        "execute_sql",
        "run_shell",
        "read_any_file",
        "write_any_file",
        "call_arbitrary_core_method",
        "plugin:fs|read_file",
        "plugin:shell|execute",
        "plugin:http|fetch",
        "plugin:clipboard-manager|read_text",
        "plugin:event|listen",
        "plugin:window|close",
        "plugin:webview|create_webview",
        "plugin:app|version",
        "plugin:path|resolve_directory",
    ] {
        assert!(get_ipc_response(&window, request(command, local_origin(), question())).is_err());
    }
}
