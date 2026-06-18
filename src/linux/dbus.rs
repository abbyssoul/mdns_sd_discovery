use zbus::proxy;

/// Avahi protocol constant: unspecified address family (IPv4 or IPv6).
pub const AVAHI_PROTO_UNSPEC: i32 = -1;
/// Avahi interface constant: unspecified (all) interfaces.
pub const AVAHI_IF_UNSPEC: i32 = -1;

/// The resolved data returned by `Server.ResolveService`:
/// `(interface, protocol, name, type, domain, host, aprotocol, address, port, txt, flags)`.
pub type ResolvedService = (
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

#[proxy(
    interface = "org.freedesktop.Avahi.Server",
    default_service = "org.freedesktop.Avahi",
    default_path = "/"
)]
pub trait Avahi {
    #[zbus(object = "ServiceTypeBrowser")]
    fn service_type_browser_new(&self, interface: i32, protocol: i32, domain: &str, flags: u32);

    #[zbus(object = "ServiceBrowser")]
    fn service_browser_new(
        &self,
        interface: i32,
        protocol: i32,
        service_type: &str,
        domain: &str,
        flags: u32,
    );

    /// Synchronously resolves a service instance to a connectable endpoint.
    ///
    /// Unlike the signal-based `ServiceResolverNew`, this returns the resolved
    /// data directly as a method reply, avoiding any subscribe-after-create race.
    #[allow(clippy::too_many_arguments)]
    fn resolve_service(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        aprotocol: i32,
        flags: u32,
    ) -> zbus::Result<ResolvedService>;
}

// The browser objects only need `Free`; their `ItemNew`/`ItemRemove`/`Failure`
// signals are consumed via a raw `MessageStream` that is subscribed *before* the
// browser is created, so the initial (cached) signal burst is not missed.
#[proxy(
    interface = "org.freedesktop.Avahi.ServiceTypeBrowser",
    default_service = "org.freedesktop.Avahi"
)]
pub trait ServiceTypeBrowser {
    fn free(&self) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.Avahi.ServiceBrowser",
    default_service = "org.freedesktop.Avahi"
)]
pub trait ServiceBrowser {
    fn free(&self) -> zbus::Result<()>;
}
