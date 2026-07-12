#![cfg(all(unix, not(target_os = "macos")))]

//! Integration tests for the Linux Avahi backend.
//!
//! Each test starts a private `dbus-daemon`, points `DBUS_SYSTEM_BUS_ADDRESS`
//! at it (which `zbus::Connection::system()` honours) and serves a mock
//! `org.freedesktop.Avahi` implementation on that bus, so the full
//! browse/resolve pipeline is exercised without a real Avahi daemon.
//!
//! The mock keys its behaviour off the requested names: service type
//! `_failure._tcp` emits a `Failure` signal, `_new-fails._tcp` rejects the
//! browser creation call, instance name `missing` fails to resolve and
//! `hang-forever` never answers. Anything else follows the happy path.

use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard};

use zbus::zvariant::OwnedObjectPath;
use zbus::{connection, fdo, interface};

use mdns_sd_discovery::{
    BrowseEvent, ServiceBrowseError, ServiceBrowser, ServiceBrowserBuilder, ServiceResolverBuilder,
};

/// `DBUS_SYSTEM_BUS_ADDRESS` is process-global, so tests that each bring up
/// their own bus must not run concurrently.
static BUS_LOCK: Mutex<()> = Mutex::const_new(());

async fn lock_bus() -> MutexGuard<'static, ()> {
    BUS_LOCK.lock().await
}

fn set_bus_address(address: &str) {
    // SAFETY: every test serializes on BUS_LOCK and only connects (reading the
    // variable) after this call, so no thread reads the environment while it
    // is being modified.
    unsafe { std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", address) };
}

/// A private session `dbus-daemon` standing in for the system bus.
struct TestBus {
    daemon: Child,
}

impl TestBus {
    fn start() -> Self {
        let mut daemon = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon is required for the mock-Avahi tests");
        let stdout = daemon.stdout.take().expect("stdout is piped");
        let mut address = String::new();
        BufReader::new(stdout)
            .read_line(&mut address)
            .expect("dbus-daemon prints its address on stdout");
        set_bus_address(address.trim());
        Self { daemon }
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

const TYPE_BROWSER_IFACE: &str = "org.freedesktop.Avahi.ServiceTypeBrowser";
const SERVICE_BROWSER_IFACE: &str = "org.freedesktop.Avahi.ServiceBrowser";

/// `Server.ResolveService` reply tuple, mirroring `linux::dbus::ResolvedService`.
type ResolvedService = (
    i32,
    i32,
    String,
    String,
    String,
    String,
    i32,
    String,
    u16,
    Vec<Vec<u8>>,
    u32,
);

struct MockAvahi;

#[interface(name = "org.freedesktop.Avahi.Server")]
impl MockAvahi {
    async fn service_type_browser_new(
        &self,
        interface: i32,
        _protocol: i32,
        domain: &str,
        _flags: u32,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<OwnedObjectPath> {
        let path = "/mock/type_browser";
        match domain {
            "type-new-fails" => {
                return Err(fdo::Error::Failed("mock rejects type browser".into()));
            }
            "type-failure" => {
                emit(conn, path, TYPE_BROWSER_IFACE, "Failure", &"type boom").await;
            }
            _ => {
                // The same type twice (exercises dedup) plus a malformed signal
                // and an ignored member.
                for _ in 0..2 {
                    emit(
                        conn,
                        path,
                        TYPE_BROWSER_IFACE,
                        "ItemNew",
                        &(interface, -1i32, "_mock._tcp", domain, 0u32),
                    )
                    .await;
                }
                emit(conn, path, TYPE_BROWSER_IFACE, "ItemNew", &42u8).await;
                emit(conn, path, TYPE_BROWSER_IFACE, "AllForNow", &()).await;
            }
        }
        Ok(OwnedObjectPath::try_from(path).expect("valid path"))
    }

    async fn service_browser_new(
        &self,
        interface: i32,
        _protocol: i32,
        service_type: &str,
        domain: &str,
        _flags: u32,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<OwnedObjectPath> {
        let path = "/mock/service_browser";
        match service_type {
            "_new-fails._tcp" => {
                return Err(fdo::Error::Failed("mock rejects service browser".into()));
            }
            "_failure._tcp" => {
                emit(conn, path, SERVICE_BROWSER_IFACE, "Failure", &"browse boom").await;
            }
            _ => {
                // A found instance, a malformed signal of each kind, an
                // ignored member, and a removed instance.
                let iface = if interface < 0 { 7 } else { interface };
                emit(
                    conn,
                    path,
                    SERVICE_BROWSER_IFACE,
                    "ItemNew",
                    &(iface, -1i32, "Mock Service", service_type, domain, 0u32),
                )
                .await;
                emit(conn, path, SERVICE_BROWSER_IFACE, "ItemNew", &42u8).await;
                emit(conn, path, SERVICE_BROWSER_IFACE, "AllForNow", &()).await;
                emit(
                    conn,
                    path,
                    SERVICE_BROWSER_IFACE,
                    "ItemRemove",
                    &(iface, -1i32, "Gone Service", service_type, domain, 0u32),
                )
                .await;
                emit(conn, path, SERVICE_BROWSER_IFACE, "ItemRemove", &42u8).await;
            }
        }
        Ok(OwnedObjectPath::try_from(path).expect("valid path"))
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_service(
        &self,
        interface: i32,
        _protocol: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        _aprotocol: i32,
        _flags: u32,
    ) -> fdo::Result<ResolvedService> {
        match name {
            "hang-forever" => {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Err(fdo::Error::Failed("should have timed out".into()))
            }
            "missing" => Err(fdo::Error::Failed("no such service".into())),
            _ => Ok((
                interface,
                -1,
                name.to_string(),
                service_type.to_string(),
                domain.to_string(),
                "mock-host.local".to_string(),
                -1,
                "192.168.7.42".to_string(),
                8080,
                vec![b"path=/mock".to_vec(), b"flag".to_vec()],
                0,
            )),
        }
    }
}

async fn emit<B>(conn: &zbus::Connection, path: &str, iface: &str, member: &str, body: &B)
where
    B: zbus::export::serde::ser::Serialize + zbus::zvariant::DynamicType,
{
    conn.emit_signal(None::<&str>, path, iface, member, body)
        .await
        .expect("mock emits signal");
}

/// Connects the mock to the private bus under the well-known Avahi name.
async fn serve_mock() -> zbus::Connection {
    let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("TestBus sets the address");
    connection::Builder::address(address.as_str())
        .expect("valid bus address")
        .name("org.freedesktop.Avahi")
        .expect("valid bus name")
        .serve_at("/", MockAvahi)
        .expect("valid object path")
        .build()
        .await
        .expect("mock Avahi connects to the private bus")
}

async fn next_event(
    browser: &mut ServiceBrowser,
) -> Option<Result<BrowseEvent, ServiceBrowseError>> {
    tokio::time::timeout(Duration::from_secs(10), browser.recv())
        .await
        .expect("timed out waiting for a browse event")
}

/// Receives events until both a `Found` and a `Removed` arrived.
async fn collect_found_and_removed(
    browser: &mut ServiceBrowser,
) -> (
    mdns_sd_discovery::DiscoveredService,
    mdns_sd_discovery::RemovedService,
) {
    let mut found = None;
    let mut removed = None;
    while found.is_none() || removed.is_none() {
        match next_event(browser)
            .await
            .expect("stream stays open until both events arrive")
            .expect("no error events on the happy path")
        {
            BrowseEvent::Found(svc) => found = Some(svc),
            BrowseEvent::Removed(svc) => removed = Some(svc),
        }
    }
    (found.expect("just set"), removed.expect("just set"))
}

#[tokio::test]
async fn browse_all_types_emits_found_and_removed() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let mut browser = ServiceBrowserBuilder::new()
        .browse()
        .await
        .expect("browse starts");
    let (found, removed) = collect_found_and_removed(&mut browser).await;

    assert_eq!(found.name, "Mock Service");
    assert_eq!(found.service_type, "_mock._tcp");
    assert_eq!(found.host_name, "mock-host.local");
    assert_eq!(found.port, 8080);
    assert_eq!(
        found.addresses,
        vec![IpAddr::from_str("192.168.7.42").expect("valid address")]
    );
    assert_eq!(found.txt("path"), Some(&b"/mock"[..]));
    assert_eq!(found.txt("flag"), None);
    assert_eq!(found.interface_index, NonZeroU32::new(7));

    assert_eq!(removed.name, "Gone Service");
    assert_eq!(removed.service_type, "_mock._tcp");
    assert_eq!(removed.interface_index, NonZeroU32::new(7));
}

#[tokio::test]
async fn browse_single_type_uses_requested_type_and_interface() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let mut browser = ServiceBrowserBuilder::new()
        .service_type("_printer._tcp")
        .domain("local")
        .interface_index(NonZeroU32::new(2).expect("non-zero"))
        .browse()
        .await
        .expect("browse starts");
    let (found, removed) = collect_found_and_removed(&mut browser).await;

    assert_eq!(found.service_type, "_printer._tcp");
    assert_eq!(found.domain, "local");
    assert_eq!(found.interface_index, NonZeroU32::new(2));
    assert_eq!(removed.service_type, "_printer._tcp");
    assert_eq!(removed.interface_index, NonZeroU32::new(2));
}

#[tokio::test]
async fn browse_surfaces_browser_failure_signal() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let mut browser = ServiceBrowserBuilder::new()
        .service_type("_failure._tcp")
        .browse()
        .await
        .expect("browse starts");
    match next_event(&mut browser)
        .await
        .expect("failure event is delivered")
    {
        Err(ServiceBrowseError::BrowseFailed(msg)) => {
            assert!(msg.contains("browse boom"), "unexpected message: {msg}");
        }
        other => panic!("expected BrowseFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn browse_surfaces_browser_creation_error_and_ends_stream() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let mut browser = ServiceBrowserBuilder::new()
        .service_type("_new-fails._tcp")
        .browse()
        .await
        .expect("browse starts; the creation error arrives via the stream");
    match next_event(&mut browser)
        .await
        .expect("error event is delivered")
    {
        Err(ServiceBrowseError::BrowseFailed(msg)) => {
            assert!(
                msg.contains("ServiceBrowserNew failed"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected BrowseFailed, got {other:?}"),
    }
    assert!(
        next_event(&mut browser).await.is_none(),
        "stream ends after fatal error"
    );
}

#[tokio::test]
async fn browse_all_surfaces_type_browser_failure_signal() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let mut browser = ServiceBrowserBuilder::new()
        .domain("type-failure")
        .browse()
        .await
        .expect("browse starts");
    match next_event(&mut browser)
        .await
        .expect("failure event is delivered")
    {
        Err(ServiceBrowseError::BrowseFailed(msg)) => {
            assert!(msg.contains("type boom"), "unexpected message: {msg}");
        }
        other => panic!("expected BrowseFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn browse_all_surfaces_type_browser_creation_error_and_ends_stream() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let mut browser = ServiceBrowserBuilder::new()
        .domain("type-new-fails")
        .browse()
        .await
        .expect("browse starts; the creation error arrives via the stream");
    match next_event(&mut browser)
        .await
        .expect("error event is delivered")
    {
        Err(ServiceBrowseError::BrowseFailed(msg)) => {
            assert!(
                msg.contains("ServiceTypeBrowserNew failed"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected BrowseFailed, got {other:?}"),
    }
    assert!(
        next_event(&mut browser).await.is_none(),
        "stream ends after fatal error"
    );
}

#[tokio::test]
async fn resolver_resolves_live_instance() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let service = ServiceResolverBuilder::new("My Service", "_mock._tcp", "local")
        .resolve()
        .await
        .expect("resolve succeeds");
    assert_eq!(service.name, "My Service");
    assert_eq!(service.service_type, "_mock._tcp");
    assert_eq!(service.domain, "local");
    assert_eq!(service.host_name, "mock-host.local");
    assert_eq!(service.port, 8080);
    // The resolve was not narrowed to an interface, so the mock echoes the
    // unspecified interface back.
    assert_eq!(service.interface_index, None);
}

#[tokio::test]
async fn resolver_with_timeout_and_interface_resolves() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let mut builder = ServiceResolverBuilder::new("My Service", "_mock._tcp", "local");
    builder
        .interface_index(NonZeroU32::new(4).expect("non-zero"))
        .timeout(Duration::from_secs(5));
    let service = builder
        .resolve()
        .await
        .expect("resolve succeeds within the timeout");
    assert_eq!(service.interface_index, NonZeroU32::new(4));
}

#[tokio::test]
async fn resolver_reports_gone_instance() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    match ServiceResolverBuilder::new("missing", "_mock._tcp", "local")
        .resolve()
        .await
    {
        Err(ServiceBrowseError::ResolveFailed(name, reason)) => {
            assert_eq!(name, "missing");
            assert!(
                reason.contains("no such service"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected ResolveFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn resolver_times_out_on_unresponsive_instance() {
    let _lock = lock_bus().await;
    let _bus = TestBus::start();
    let _mock = serve_mock().await;

    let mut builder = ServiceResolverBuilder::new("hang-forever", "_mock._tcp", "local");
    builder.timeout(Duration::from_millis(200));
    match builder.resolve().await {
        Err(ServiceBrowseError::ResolveFailed(name, reason)) => {
            assert_eq!(name, "hang-forever");
            assert!(
                reason.contains("timed out after"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected ResolveFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn browse_and_resolve_fail_without_system_bus() {
    let _lock = lock_bus().await;
    set_bus_address("unix:path=/nonexistent/mock-bus-socket");

    match ServiceBrowserBuilder::new().browse().await {
        Err(ServiceBrowseError::DnsSdUnavailable(msg)) => {
            assert!(msg.contains("system D-Bus"), "unexpected message: {msg}");
        }
        Err(other) => panic!("expected DnsSdUnavailable, got {other:?}"),
        Ok(_) => panic!("expected DnsSdUnavailable, got a live browser"),
    }
    match ServiceResolverBuilder::new("x", "_x._tcp", "local")
        .resolve()
        .await
    {
        Err(ServiceBrowseError::DnsSdUnavailable(msg)) => {
            assert!(msg.contains("system D-Bus"), "unexpected message: {msg}");
        }
        other => panic!("expected DnsSdUnavailable, got {other:?}"),
    }
}
