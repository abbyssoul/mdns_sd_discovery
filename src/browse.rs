use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use thiserror::Error;
use tokio::sync::mpsc;

#[cfg(all(unix, not(target_os = "macos")))]
use crate::linux::{BrowseGuard, browse_start};
#[cfg(target_os = "macos")]
use crate::macos::{BrowseGuard, browse_start};
#[cfg(target_os = "windows")]
use crate::windows::{BrowseGuard, browse_start};

/// Sender used by platform back-ends to publish discovery events.
pub(crate) type BrowseEventSender = mpsc::UnboundedSender<Result<BrowseEvent, ServiceBrowseError>>;
/// Receiver held by [`ServiceBrowser`] to deliver discovery events to the caller.
pub(crate) type BrowseEventReceiver =
    mpsc::UnboundedReceiver<Result<BrowseEvent, ServiceBrowseError>>;

/// Builder for a DNS-SD service browse (discovery) operation.
///
/// By default a browser discovers **all** service types advertised on the
/// network and reports the instances of each (using the DNS-SD service-type
/// enumeration meta-query, see [RFC 6763 §9](https://datatracker.ietf.org/doc/html/rfc6763#section-9)).
/// Filter on [`DiscoveredService::service_type`] for the types you care about,
/// or call [`service_type`](Self::service_type) to narrow to a single type.
///
/// # Example
///
/// ```no_run
/// use mdns_sd_discovery::{BrowseEvent, ServiceBrowserBuilder};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut browser = ServiceBrowserBuilder::new().browse().await?;
/// while let Some(event) = browser.recv().await {
///     match event? {
///         BrowseEvent::Found(svc) => println!("+ {} {}:{}", svc.name, svc.host_name, svc.port),
///         BrowseEvent::Removed(svc) => println!("- {}", svc.name),
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct ServiceBrowserBuilder {
    /// `None` means browse every service type via the meta-query cascade.
    pub(crate) service_type: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) interface_index: Option<NonZeroU32>,
}

impl ServiceBrowserBuilder {
    /// Initializes a builder that browses for **all** service types on the network.
    ///
    /// Call [`service_type`](Self::service_type) to narrow to a single type.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts browsing to a single service type, e.g. `_http._tcp`.
    ///
    /// The service type is the service followed by the transport protocol,
    /// separated by a dot (e.g. `_ftp._tcp`). When unset (the default), all
    /// service types are discovered via the DNS-SD meta-query
    /// (`_services._dns-sd._udp`); setting a type skips the meta-query and
    /// browses that type directly.
    pub fn service_type(&mut self, service_type: impl AsRef<str>) -> &mut Self {
        self.service_type = Some(service_type.as_ref().to_string());
        self
    }

    /// Browses a specific domain.
    ///
    /// Most applications will not specify a domain, instead browsing the
    /// default browse domain(s) (usually `local`).
    pub fn domain(&mut self, domain: impl AsRef<str>) -> &mut Self {
        self.domain = Some(domain.as_ref().to_string());
        self
    }

    /// Restricts browsing to a single interface
    /// (the index for a given interface is determined via the `if_nametoindex()`
    /// family of calls.)
    ///
    /// Most applications will not specify an interface, instead browsing on all
    /// available interfaces.
    pub fn interface_index(&mut self, index: NonZeroU32) -> &mut Self {
        self.interface_index = Some(index);
        self
    }

    /// Starts browsing, returning a live [`ServiceBrowser`] handle.
    ///
    /// The browse runs until the returned handle is dropped.
    pub async fn browse(&self) -> Result<ServiceBrowser, ServiceBrowseError> {
        let (rx, guard) =
            browse_start(&self.service_type, &self.domain, self.interface_index).await?;
        Ok(ServiceBrowser { rx, _guard: guard })
    }
}

/// A live handle to an ongoing browse operation.
///
/// Call [`recv`](Self::recv) to await discovery events. The underlying native
/// browse operation is stopped when this handle is dropped.
pub struct ServiceBrowser {
    rx: BrowseEventReceiver,
    /// Platform guard whose `Drop` tears down the native browse operation.
    _guard: BrowseGuard,
}

impl ServiceBrowser {
    /// Awaits the next discovery event.
    ///
    /// Returns `None` once the browse has terminated (the back-end shut down or
    /// the handle is being dropped). A failure to resolve an individual service
    /// is reported as `Some(Err(..))` and does **not** end the stream.
    pub async fn recv(&mut self) -> Option<Result<BrowseEvent, ServiceBrowseError>> {
        self.rx.recv().await
    }
}

/// A single change in the set of discovered services.
#[derive(Debug, Clone)]
pub enum BrowseEvent {
    /// A service appeared and was resolved to a connectable endpoint.
    Found(DiscoveredService),
    /// A previously seen service went away. Only identity fields are known.
    Removed(RemovedService),
}

/// A resolved, connectable service instance.
#[derive(Debug, Clone)]
pub struct DiscoveredService {
    /// The service instance name, e.g. `My Web Server`.
    pub name: String,
    /// The service type, e.g. `_http._tcp`.
    pub service_type: String,
    /// The domain the service was discovered in, e.g. `local`.
    pub domain: String,
    /// The SRV target host name, e.g. `macbook.local`.
    pub host_name: String,
    /// The port the service accepts connections on.
    pub port: u16,
    /// Resolved IP addresses for [`host_name`](Self::host_name). May be empty
    /// if address resolution did not (yet) yield any records.
    pub addresses: Vec<IpAddr>,
    /// The service's TXT record entries.
    pub txt_records: Vec<TxtRecord>,
    /// The interface the service was discovered on, if known.
    pub interface_index: Option<NonZeroU32>,
}

impl DiscoveredService {
    /// Returns the resolved socket addresses (each [address](Self::addresses)
    /// paired with the [port](Self::port)).
    pub fn socket_addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.addresses
            .iter()
            .map(move |&ip| SocketAddr::new(ip, self.port))
    }

    /// Returns the value of the first TXT record entry matching `key`, if any.
    ///
    /// Returns `Some(&[])` for a key that is present with an empty value and
    /// `None` for a key that is absent or key-only.
    pub fn txt(&self, key: &str) -> Option<&[u8]> {
        self.txt_records
            .iter()
            .find(|r| r.key == key)
            .and_then(|r| r.value.as_deref())
    }
}

/// Identity of a service instance that disappeared.
///
/// Browsing does not provide resolved data on removal, so only the identifying
/// fields are available.
#[derive(Debug, Clone)]
pub struct RemovedService {
    /// The service instance name.
    pub name: String,
    /// The service type, e.g. `_http._tcp`.
    pub service_type: String,
    /// The domain the service was discovered in.
    pub domain: String,
    /// The interface the service was discovered on, if known.
    pub interface_index: Option<NonZeroU32>,
}

/// A single TXT record key/value entry.
///
/// `value` is binary-safe and is `None` for a key-only entry (a key advertised
/// without an `=`).
#[derive(Debug, Clone)]
pub struct TxtRecord {
    /// The TXT record key.
    pub key: String,
    /// The TXT record value, or `None` for a key-only entry.
    pub value: Option<Vec<u8>>,
}

/// Error type for service browse / discovery failures.
#[derive(Error, Debug)]
pub enum ServiceBrowseError {
    /// DNS-SD not available on system (Linux only - either D-Bus or Avahi unavailable).
    #[error("DNS-SD not available on system: {0}")]
    DnsSdUnavailable(String),

    /// A string parameter contains an interior NUL byte.
    #[error("parameter {0:?} contains interior nul byte at position {1}")]
    ParameterContainsInteriorNulByte(String, usize),

    /// The interface index is not valid.
    #[error("interface index {0} is invalid")]
    InvalidInterfaceIndex(u32),

    /// The browse operation failed.
    #[error("browse operation failed: {0}")]
    BrowseFailed(String),

    /// A discovered service could not be resolved to a connectable endpoint.
    #[error("failed to resolve service {0:?}: {1}")]
    ResolveFailed(String, String),
}

/// Parses a single `key` or `key=value` TXT entry into a [`TxtRecord`].
///
/// Everything before the first `=` is the key; everything after is the
/// (binary-safe) value. An entry with no `=` is key-only.
#[cfg(unix)]
pub(crate) fn parse_txt_entry(entry: &[u8]) -> TxtRecord {
    match entry.iter().position(|&b| b == b'=') {
        Some(pos) => TxtRecord {
            key: String::from_utf8_lossy(&entry[..pos]).into_owned(),
            value: Some(entry[pos + 1..].to_vec()),
        },
        None => TxtRecord {
            key: String::from_utf8_lossy(entry).into_owned(),
            value: None,
        },
    }
}

/// Parses a packed DNS-SD TXT record buffer (a sequence of length-prefixed
/// `key[=value]` entries) into [`TxtRecord`]s. Empty entries are skipped.
#[cfg(target_os = "macos")]
pub(crate) fn parse_txt_buffer(buf: &[u8]) -> Vec<TxtRecord> {
    let mut records = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let len = buf[i] as usize;
        i += 1;
        if i + len > buf.len() {
            break;
        }
        if len > 0 {
            records.push(parse_txt_entry(&buf[i..i + len]));
        }
        i += len;
    }
    records
}
