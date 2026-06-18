use std::collections::HashSet;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::str::FromStr;

use futures_util::stream::StreamExt;
use log::{trace, warn};
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinHandle;
use zbus::message::Type as MessageType;
use zbus::{Connection, MatchRule, MessageStream};

use super::dbus::*;
use crate::browse::{
    BrowseEvent, BrowseEventReceiver, BrowseEventSender, DiscoveredService, RemovedService,
    ServiceBrowseError, parse_txt_entry,
};

const SERVICE_BROWSER_INTERFACE: &str = "org.freedesktop.Avahi.ServiceBrowser";
const SERVICE_TYPE_BROWSER_INTERFACE: &str = "org.freedesktop.Avahi.ServiceTypeBrowser";

/// Guard returned alongside the event receiver. Dropping it aborts the root
/// browse task, which in turn drops (and thereby aborts) any child browse and
/// resolver tasks it owns.
pub(crate) struct BrowseGuard {
    handle: JoinHandle<()>,
}

impl Drop for BrowseGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Aborts the wrapped task when dropped. Used to tie child task lifetimes to the
/// parent task that owns them.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn browse_start(
    service_type: &Option<String>,
    domain: &Option<String>,
    interface_index: Option<NonZeroU32>,
) -> Result<(BrowseEventReceiver, BrowseGuard), ServiceBrowseError> {
    // Validate Avahi is reachable up front so the error surfaces from `browse()`
    // rather than asynchronously through the event stream.
    let conn = Connection::system().await.map_err(|err| {
        ServiceBrowseError::DnsSdUnavailable(format!("failed to connect to system D-Bus: {err}"))
    })?;
    AvahiProxy::new(&conn).await.map_err(|err| {
        ServiceBrowseError::DnsSdUnavailable(format!("failed to connect to Avahi via D-Bus: {err}"))
    })?;
    drop(conn);

    let interface = interface_to_avahi(interface_index)?;
    let domain = domain.clone().unwrap_or_default();
    let (tx, rx) = unbounded_channel();

    let handle = match service_type {
        Some(service_type) => {
            let service_type = service_type.clone();
            tokio::spawn(browse_one_type(interface, service_type, domain, tx))
        }
        None => tokio::spawn(browse_all_types(interface, domain, tx)),
    };

    Ok((rx, BrowseGuard { handle }))
}

/// Subscribes to all signals of `interface` on a freshly created, dedicated
/// connection *before* any browser object is created, so the initial burst of
/// cached-entry signals is not missed. Returns the connection, an Avahi server
/// proxy on it, and the message stream.
async fn connect_and_subscribe(
    interface: &str,
) -> Result<(Connection, MessageStream), ServiceBrowseError> {
    let conn = Connection::system().await.map_err(|err| {
        ServiceBrowseError::DnsSdUnavailable(format!("failed to connect to system D-Bus: {err}"))
    })?;

    let rule = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .sender("org.freedesktop.Avahi")
        .and_then(|b| b.interface(interface))
        .map_err(|err| ServiceBrowseError::BrowseFailed(err.to_string()))?
        .build();

    let messages = MessageStream::for_match_rule(rule, &conn, None)
        .await
        .map_err(|err| ServiceBrowseError::BrowseFailed(err.to_string()))?;

    Ok((conn, messages))
}

/// Browses the DNS-SD service-type meta-query and starts a per-type instance
/// browse for each newly discovered type.
async fn browse_all_types(interface: i32, domain: String, tx: BrowseEventSender) {
    let (conn, mut messages) = match connect_and_subscribe(SERVICE_TYPE_BROWSER_INTERFACE).await {
        Ok(parts) => parts,
        Err(err) => {
            let _ = tx.send(Err(err));
            return;
        }
    };

    let server = match AvahiProxy::new(&conn).await {
        Ok(server) => server,
        Err(err) => {
            let _ = tx.send(Err(ServiceBrowseError::DnsSdUnavailable(err.to_string())));
            return;
        }
    };

    let type_browser = match server
        .service_type_browser_new(interface, AVAHI_PROTO_UNSPEC, &domain, 0)
        .await
    {
        Ok(browser) => browser,
        Err(err) => {
            let _ = tx.send(Err(ServiceBrowseError::BrowseFailed(format!(
                "ServiceTypeBrowserNew failed: {err}"
            ))));
            return;
        }
    };

    // Dedup discovered types (a type may be announced on multiple interfaces) and
    // keep each per-type instance browse alive for our lifetime.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut child_browsers: Vec<AbortOnDrop> = Vec::new();

    while let Some(msg) = messages.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(err) => {
                warn!("service type browser message error: {err}");
                continue;
            }
        };
        let member = msg.header().member().map(|m| m.as_str().to_owned());
        match member.as_deref() {
            Some("ItemNew") => {
                let (_iface, _proto, service_type, item_domain, _flags): (
                    i32,
                    i32,
                    String,
                    String,
                    u32,
                ) = match msg.body().deserialize() {
                    Ok(args) => args,
                    Err(err) => {
                        warn!("malformed service type ItemNew: {err}");
                        continue;
                    }
                };
                if seen.insert((service_type.clone(), item_domain.clone())) {
                    trace!("discovered service type {service_type:?} in domain {item_domain:?}");
                    let handle = tokio::spawn(browse_one_type(
                        interface,
                        service_type,
                        item_domain,
                        tx.clone(),
                    ));
                    child_browsers.push(AbortOnDrop(handle));
                }
            }
            Some("Failure") => {
                let err: String = msg.body().deserialize().unwrap_or_default();
                let _ = tx.send(Err(ServiceBrowseError::BrowseFailed(format!(
                    "service type browser failure: {err}"
                ))));
            }
            _ => {} // ItemRemove (of a type), AllForNow, CacheExhausted
        }
    }

    let _ = type_browser.free().await;
}

/// Browses instances of a single service type, resolving each as it appears.
async fn browse_one_type(
    interface: i32,
    service_type: String,
    domain: String,
    tx: BrowseEventSender,
) {
    let (conn, mut messages) = match connect_and_subscribe(SERVICE_BROWSER_INTERFACE).await {
        Ok(parts) => parts,
        Err(err) => {
            let _ = tx.send(Err(err));
            return;
        }
    };

    let server = match AvahiProxy::new(&conn).await {
        Ok(server) => server,
        Err(err) => {
            let _ = tx.send(Err(ServiceBrowseError::DnsSdUnavailable(err.to_string())));
            return;
        }
    };

    let browser = match server
        .service_browser_new(interface, AVAHI_PROTO_UNSPEC, &service_type, &domain, 0)
        .await
    {
        Ok(browser) => browser,
        Err(err) => {
            let _ = tx.send(Err(ServiceBrowseError::BrowseFailed(format!(
                "ServiceBrowserNew failed for {service_type}: {err}"
            ))));
            return;
        }
    };

    // In-flight resolver tasks; aborted when this task ends.
    let mut resolvers: Vec<AbortOnDrop> = Vec::new();

    while let Some(msg) = messages.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(err) => {
                warn!("service browser message error: {err}");
                continue;
            }
        };
        let member = msg.header().member().map(|m| m.as_str().to_owned());
        match member.as_deref() {
            Some("ItemNew") => {
                let (iface, protocol, name, item_type, item_domain, _flags): (
                    i32,
                    i32,
                    String,
                    String,
                    String,
                    u32,
                ) = match msg.body().deserialize() {
                    Ok(args) => args,
                    Err(err) => {
                        warn!("malformed ItemNew: {err}");
                        continue;
                    }
                };
                resolvers.retain(|r| !r.0.is_finished());
                let handle = tokio::spawn(resolve_and_emit(
                    conn.clone(),
                    iface,
                    protocol,
                    name,
                    item_type,
                    item_domain,
                    tx.clone(),
                ));
                resolvers.push(AbortOnDrop(handle));
            }
            Some("ItemRemove") => {
                let (iface, _protocol, name, item_type, item_domain, _flags): (
                    i32,
                    i32,
                    String,
                    String,
                    String,
                    u32,
                ) = match msg.body().deserialize() {
                    Ok(args) => args,
                    Err(err) => {
                        warn!("malformed ItemRemove: {err}");
                        continue;
                    }
                };
                let removed = RemovedService {
                    name,
                    service_type: item_type,
                    domain: item_domain,
                    interface_index: avahi_interface_to_index(iface),
                };
                if tx.send(Ok(BrowseEvent::Removed(removed))).is_err() {
                    break;
                }
            }
            Some("Failure") => {
                let err: String = msg.body().deserialize().unwrap_or_default();
                let _ = tx.send(Err(ServiceBrowseError::BrowseFailed(format!(
                    "service browser failure for {service_type}: {err}"
                ))));
            }
            _ => {} // AllForNow, CacheExhausted
        }
    }

    let _ = browser.free().await;
}

/// Resolves a single discovered service instance via the synchronous
/// `Server.ResolveService` method and emits a `Found` event (or a
/// `ResolveFailed` error). Using the method (rather than the signal-based
/// `ServiceResolverNew`) avoids the subscribe-after-create signal race.
async fn resolve_and_emit(
    conn: Connection,
    interface: i32,
    protocol: i32,
    name: String,
    service_type: String,
    domain: String,
    tx: BrowseEventSender,
) {
    let server = match AvahiProxy::new(&conn).await {
        Ok(server) => server,
        Err(err) => {
            let _ = tx.send(Err(ServiceBrowseError::ResolveFailed(
                name,
                err.to_string(),
            )));
            return;
        }
    };

    match server
        .resolve_service(
            interface,
            protocol,
            &name,
            &service_type,
            &domain,
            AVAHI_PROTO_UNSPEC,
            0,
        )
        .await
    {
        Ok((
            iface,
            _proto,
            name,
            service_type,
            domain,
            host,
            _aproto,
            address,
            port,
            txt,
            _flags,
        )) => {
            let addresses: Vec<IpAddr> = IpAddr::from_str(&address).ok().into_iter().collect();
            let txt_records = txt.iter().map(|entry| parse_txt_entry(entry)).collect();
            let service = DiscoveredService {
                name,
                service_type,
                domain,
                host_name: host,
                port,
                addresses,
                txt_records,
                interface_index: avahi_interface_to_index(iface),
            };
            let _ = tx.send(Ok(BrowseEvent::Found(service)));
        }
        Err(err) => {
            let _ = tx.send(Err(ServiceBrowseError::ResolveFailed(
                name,
                err.to_string(),
            )));
        }
    }
}

/// Maps an optional interface index to Avahi's `i32` interface argument.
fn interface_to_avahi(interface_index: Option<NonZeroU32>) -> Result<i32, ServiceBrowseError> {
    match interface_index {
        Some(i) => {
            let idx = i.get();
            if idx > i32::MAX as u32 {
                return Err(ServiceBrowseError::InvalidInterfaceIndex(idx));
            }
            Ok(idx as i32)
        }
        None => Ok(AVAHI_IF_UNSPEC),
    }
}

/// Maps an Avahi `i32` interface value from a signal back to an interface index.
fn avahi_interface_to_index(interface: i32) -> Option<NonZeroU32> {
    if interface <= 0 {
        None
    } else {
        NonZeroU32::new(interface as u32)
    }
}
