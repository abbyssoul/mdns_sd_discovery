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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample_service() -> DiscoveredService {
        DiscoveredService {
            name: "My Web Server".to_string(),
            service_type: "_http._tcp".to_string(),
            domain: "local".to_string(),
            host_name: "macbook.local".to_string(),
            port: 8080,
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            txt_records: vec![
                TxtRecord {
                    key: "path".to_string(),
                    value: Some(b"/index.html".to_vec()),
                },
                TxtRecord {
                    key: "empty".to_string(),
                    value: Some(Vec::new()),
                },
                TxtRecord {
                    key: "flag".to_string(),
                    value: None,
                },
            ],
            interface_index: NonZeroU32::new(3),
        }
    }

    #[test]
    fn builder_defaults_to_browsing_all_types() {
        let builder = ServiceBrowserBuilder::new();
        assert_eq!(builder.service_type, None);
        assert_eq!(builder.domain, None);
        assert_eq!(builder.interface_index, None);
    }

    #[test]
    fn builder_default_matches_new() {
        let from_default = ServiceBrowserBuilder::default();
        let from_new = ServiceBrowserBuilder::new();
        assert_eq!(from_default.service_type, from_new.service_type);
        assert_eq!(from_default.domain, from_new.domain);
        assert_eq!(from_default.interface_index, from_new.interface_index);
    }

    #[test]
    fn builder_setters_record_values_and_chain() {
        let mut builder = ServiceBrowserBuilder::new();
        builder
            .service_type("_http._tcp")
            .domain("local")
            .interface_index(NonZeroU32::new(7).unwrap());

        assert_eq!(builder.service_type.as_deref(), Some("_http._tcp"));
        assert_eq!(builder.domain.as_deref(), Some("local"));
        assert_eq!(builder.interface_index, NonZeroU32::new(7));
    }

    #[test]
    fn builder_setters_accept_string_and_overwrite() {
        let mut builder = ServiceBrowserBuilder::new();
        builder.service_type(String::from("_ftp._tcp"));
        builder.service_type("_ipp._tcp");
        assert_eq!(builder.service_type.as_deref(), Some("_ipp._tcp"));
    }

    #[test]
    fn socket_addrs_pairs_each_address_with_port() {
        let service = sample_service();
        let addrs: Vec<SocketAddr> = service.socket_addrs().collect();
        assert_eq!(
            addrs,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8080),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
            ]
        );
    }

    #[test]
    fn socket_addrs_is_empty_without_addresses() {
        let mut service = sample_service();
        service.addresses.clear();
        assert_eq!(service.socket_addrs().count(), 0);
    }

    #[test]
    fn txt_returns_value_for_present_key() {
        let service = sample_service();
        assert_eq!(service.txt("path"), Some(&b"/index.html"[..]));
    }

    #[test]
    fn txt_returns_empty_slice_for_present_empty_value() {
        let service = sample_service();
        assert_eq!(service.txt("empty"), Some(&[][..]));
    }

    #[test]
    fn txt_returns_none_for_key_only_entry() {
        let service = sample_service();
        assert_eq!(service.txt("flag"), None);
    }

    #[test]
    fn txt_returns_none_for_absent_key() {
        let service = sample_service();
        assert_eq!(service.txt("missing"), None);
    }

    #[test]
    fn txt_returns_first_match_for_duplicate_keys() {
        let mut service = sample_service();
        service.txt_records.push(TxtRecord {
            key: "path".to_string(),
            value: Some(b"/second".to_vec()),
        });
        assert_eq!(service.txt("path"), Some(&b"/index.html"[..]));
    }

    #[test]
    fn error_messages_render_expected_text() {
        assert_eq!(
            ServiceBrowseError::DnsSdUnavailable("no avahi".into()).to_string(),
            "DNS-SD not available on system: no avahi"
        );
        assert_eq!(
            ServiceBrowseError::ParameterContainsInteriorNulByte("a\0b".into(), 1).to_string(),
            "parameter \"a\\0b\" contains interior nul byte at position 1"
        );
        assert_eq!(
            ServiceBrowseError::InvalidInterfaceIndex(42).to_string(),
            "interface index 42 is invalid"
        );
        assert_eq!(
            ServiceBrowseError::BrowseFailed("boom".into()).to_string(),
            "browse operation failed: boom"
        );
        assert_eq!(
            ServiceBrowseError::ResolveFailed("svc".into(), "timeout".into()).to_string(),
            "failed to resolve service \"svc\": timeout"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_txt_entry_splits_key_and_value() {
        let record = parse_txt_entry(b"path=/index.html");
        assert_eq!(record.key, "path");
        assert_eq!(record.value.as_deref(), Some(&b"/index.html"[..]));
    }

    #[cfg(unix)]
    #[test]
    fn parse_txt_entry_empty_value_after_equals() {
        let record = parse_txt_entry(b"key=");
        assert_eq!(record.key, "key");
        assert_eq!(record.value.as_deref(), Some(&[][..]));
    }

    #[cfg(unix)]
    #[test]
    fn parse_txt_entry_key_only_has_no_value() {
        let record = parse_txt_entry(b"flag");
        assert_eq!(record.key, "flag");
        assert_eq!(record.value, None);
    }

    #[cfg(unix)]
    #[test]
    fn parse_txt_entry_splits_on_first_equals_only() {
        let record = parse_txt_entry(b"k=a=b");
        assert_eq!(record.key, "k");
        assert_eq!(record.value.as_deref(), Some(&b"a=b"[..]));
    }

    #[cfg(unix)]
    #[test]
    fn parse_txt_entry_preserves_binary_value() {
        let record = parse_txt_entry(b"bin=\x00\xff\x01");
        assert_eq!(record.key, "bin");
        assert_eq!(record.value.as_deref(), Some(&[0x00, 0xff, 0x01][..]));
    }

    #[cfg(unix)]
    #[test]
    fn parse_txt_entry_lossily_decodes_invalid_utf8_key() {
        let record = parse_txt_entry(b"\xff\xffkey");
        assert!(record.key.contains('\u{FFFD}'));
        assert_eq!(record.value, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_txt_buffer_reads_length_prefixed_entries() {
        // "a=1" (3) , "flag" (4)
        let buf = [3u8, b'a', b'=', b'1', 4u8, b'f', b'l', b'a', b'g'];
        let records = parse_txt_buffer(&buf);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].key, "a");
        assert_eq!(records[0].value.as_deref(), Some(&b"1"[..]));
        assert_eq!(records[1].key, "flag");
        assert_eq!(records[1].value, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_txt_buffer_skips_empty_entries() {
        let buf = [0u8, 3u8, b'a', b'=', b'1'];
        let records = parse_txt_buffer(&buf);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, "a");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_txt_buffer_stops_on_truncated_entry() {
        // claims length 5 but only 2 bytes follow
        let buf = [5u8, b'a', b'b'];
        assert!(parse_txt_buffer(&buf).is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_txt_buffer_empty_input_yields_no_records() {
        assert!(parse_txt_buffer(&[]).is_empty());
    }
}
