//! TA-03 negative control inside a test binary: under `tools/ci/ta03_isolated.sh`, a
//! direct socket must fail. Elsewhere this test does nothing, so it proves nothing there.
//! It is the one place allowed to name a socket type: `clippy.toml` bans them everywhere else.
#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[test]
fn outbound_socket_is_denied_under_isolation() {
    if std::env::var("SAFEEVIDENCE_TA03_ISOLATED").as_deref() != Ok("1") {
        return;
    }
    let target: SocketAddr = "1.1.1.1:443".parse().expect("literal address");
    let attempt = TcpStream::connect_timeout(&target, Duration::from_secs(10));
    assert!(
        attempt.is_err(),
        "outbound socket succeeded under isolation"
    );
    println!("TA-03 test-binary control: {:?}", attempt.err());
}
