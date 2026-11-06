//! Linux keyring helper: serves `safeevidence-keyring-wire` requests on stdin and stdout, so that
//! D-Bus and its sockets stay out of the core process. It prints nothing else to stdout. It reads and
//! writes through unbuffered handles, because std's stdin and stdout buffers would keep whole records
//! in memory after the frames holding them are zeroized.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use std::fs::File;
    use std::os::fd::AsFd;

    let handles = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .and_then(|stdin| Ok((stdin, std::io::stdout().as_fd().try_clone_to_owned()?)));
    let Ok((stdin, stdout)) = handles else {
        return std::process::ExitCode::FAILURE;
    };
    let mut backend = safeevidence_linux_keyring_helper::SecretServiceBackend;
    match safeevidence_keyring_wire::serve(
        &mut File::from(stdin),
        &mut File::from(stdout),
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
