#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

mod ask_command;
mod custody;
mod navigation_policy;
mod startup_failure;

#[cfg(test)]
mod permission_tests;

/// One expansion only: on macOS each `generate_context!` embeds an Info.plist symbol, so a second
/// call in the test build would define it twice.
fn app_context<R: tauri::Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

/// Every native command the frontend may call. `build.rs` declares the same
/// list in the app manifest and `capabilities/default.json` grants it to the
/// main window only; anything else is refused before it reaches Rust.
fn presentation_builder<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder
        .manage(ask_command::AskState::default())
        .invoke_handler(tauri::generate_handler![ask_command::ask_question])
}

fn main() {
    startup_failure::install_panic_hook();
    presentation_builder(tauri::Builder::default())
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            // Without this feature the variable is never read, so a shipped build ignores it.
            #[cfg(feature = "e2e")]
            let data_dir = std::env::var_os("SAFEEVIDENCE_E2E_DATA_DIR")
                .map_or(data_dir, std::path::PathBuf::from);
            let webview_dir = data_dir.join("webview");
            app.state::<ask_command::AskState>().set_data_dir(data_dir);
            let config = app
                .config()
                .app
                .windows
                .first()
                .ok_or("missing main window")?;
            let window = tauri::WebviewWindowBuilder::from_config(app, config)?
                .on_navigation(|url| {
                    navigation_policy::is_local_application_url(url, cfg!(debug_assertions))
                })
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .on_page_load(|_, payload| {
                    if payload.event() == tauri::webview::PageLoadEvent::Finished {
                        startup_failure::mark_ready();
                    }
                })
                .incognito(true)
                .data_directory(webview_dir);
            // Setting these replaces wry's default, so its default stays in the list. A shipped build does not
            // set a debugging port.
            #[cfg(all(feature = "e2e", windows))]
            let window = window.additional_browser_args(
                "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --remote-debugging-port=9333",
            );
            window.build()?;
            Ok(())
        })
        .build(app_context())
        .unwrap_or_else(|error| startup_failure::report_and_exit(&error.to_string()))
        .run(|app, event| {
            // Managed state is not guaranteed to be dropped on exit.
            if let tauri::RunEvent::Exit = event {
                app.state::<ask_command::AskState>().close();
            }
        });
}
