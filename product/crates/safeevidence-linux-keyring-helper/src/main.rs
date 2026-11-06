//! Linux keyring helper: serves `safeevidence-keyring-wire` requests on stdin and stdout, so that
//! D-Bus and its sockets stay out of the core process. It prints nothing else to stdout.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut backend = safeevidence_linux_keyring_helper::SecretServiceBackend;
    match safeevidence_keyring_wire::serve(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut backend,
    ) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
