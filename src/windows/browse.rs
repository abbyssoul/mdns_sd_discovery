use std::collections::HashSet;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, Weak};

use log::trace;
use tokio::runtime::Handle;
use tokio::sync::mpsc::unbounded_channel;
use widestring::U16CString;
use windows::Win32::NetworkManagement::Dns;
use windows::core::{PCWSTR, PWSTR};

use crate::browse::{
    BrowseEvent, BrowseEventReceiver, BrowseEventSender, DiscoveredService, ServiceBrowseError,
    TxtRecord,
};

/// The DNS-SD meta-query used to enumerate all service types on the network.
const META_QUERY_TYPE: &str = "_services._dns-sd._udp.local";
/// Default browse domain when none is specified.
const DEFAULT_DOMAIN: &str = "local";
/// `DnsServiceBrowse`/`DnsServiceResolve` return this when the request started
/// asynchronously (the completion callback will fire).
const DNS_REQUEST_PENDING: i32 = 9506;

/// Registry of active browse operations, shared (weakly) with the callbacks so
/// the meta-query cascade can register child browses.
type Registry = Arc<Mutex<Vec<BrowseEntry>>>;

/// Guard returned alongside the event receiver. Dropping it drops the registry,
/// which cancels every browse and frees its context.
pub(crate) struct BrowseGuard {
    _registry: Registry,
}

/// One active browse operation. Field order matters for `Drop`: `cancel` is
/// dropped first (cancelling the browse, after which no more callbacks fire),
/// then the context and query-name backing store are freed.
struct BrowseEntry {
    _cancel: CancelHandle,
    _context: Box<BrowseContext>,
    _query_name: U16CString,
}

/// RAII wrapper that cancels a browse when dropped.
struct CancelHandle(Dns::DNS_SERVICE_CANCEL);

// SAFETY: `DNS_SERVICE_CANCEL` is an opaque handle used only to cancel the
// browse; it is never dereferenced in Rust and is safe to move across threads.
unsafe impl Send for CancelHandle {}

impl Drop for CancelHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` was produced by a successful `DnsServiceBrowse` and is
        // cancelled exactly once here.
        unsafe {
            let _ = Dns::DnsServiceBrowseCancel(&self.0);
        }
    }
}

/// Context handed to the browse callback for one browse operation.
struct BrowseContext {
    tx: BrowseEventSender,
    handle: Handle,
    registry: Weak<Mutex<Vec<BrowseEntry>>>,
    is_meta: bool,
    /// Interface scope requested by the caller (0 = all).
    interface: u32,
    /// For instance browses: the service type being browsed.
    service_type: String,
    /// For instance browses: the domain being browsed.
    domain: String,
    /// Dedup of names already handled (instance names, or service types for meta).
    seen: Mutex<HashSet<String>>,
}

// SAFETY: every field is `Send`/`Sync` except the raw handles wrapped in
// `CancelHandle` (reachable via the weak registry), which carry their own
// `unsafe impl Send`. The context is only shared with the OS via a raw pointer.
unsafe impl Send for BrowseContext {}
unsafe impl Sync for BrowseContext {}

pub(crate) async fn browse_start(
    service_type: &Option<String>,
    domain: &Option<String>,
    interface_index: Option<NonZeroU32>,
) -> Result<(BrowseEventReceiver, BrowseGuard), ServiceBrowseError> {
    let (tx, rx) = unbounded_channel();
    let handle = Handle::current();
    let interface = interface_index.map(|i| i.get()).unwrap_or(0); // 0 = all interfaces
    let domain = domain.clone().unwrap_or_else(|| DEFAULT_DOMAIN.to_string());
    let registry: Registry = Arc::new(Mutex::new(Vec::new()));

    let (query_name, service_type, is_meta) = match service_type {
        Some(service_type) => (
            format!("{service_type}.{domain}"),
            service_type.clone(),
            false,
        ),
        None => (
            META_QUERY_TYPE.to_string(),
            META_QUERY_TYPE.to_string(),
            true,
        ),
    };

    start_browse(
        query_name,
        service_type,
        domain,
        interface,
        is_meta,
        tx,
        handle,
        &registry,
    )
    .map_err(ServiceBrowseError::BrowseFailed)?;

    Ok((
        rx,
        BrowseGuard {
            _registry: registry,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn start_browse(
    query_name: String,
    service_type: String,
    domain: String,
    interface: u32,
    is_meta: bool,
    tx: BrowseEventSender,
    handle: Handle,
    registry: &Registry,
) -> Result<(), String> {
    let query_name_w = U16CString::from_str(&query_name).map_err(|e| e.to_string())?;

    let context = Box::new(BrowseContext {
        tx,
        handle,
        registry: Arc::downgrade(registry),
        is_meta,
        interface,
        service_type,
        domain,
        seen: Mutex::new(HashSet::new()),
    });
    // The heap data behind `context` stays put when the `Box` is later moved into
    // the registry, so this pointer remains valid for the browse's lifetime.
    let context_ptr = &*context as *const BrowseContext as *mut c_void;

    let request = Dns::DNS_SERVICE_BROWSE_REQUEST {
        Version: Dns::DNS_QUERY_REQUEST_VERSION1.0,
        InterfaceIndex: interface,
        QueryName: PCWSTR(query_name_w.as_ptr()),
        Anonymous: Dns::DNS_SERVICE_BROWSE_REQUEST_0 {
            pBrowseCallback: Some(browse_callback),
        },
        pQueryContext: context_ptr,
    };

    let mut cancel = Dns::DNS_SERVICE_CANCEL::default();
    // SAFETY: `request` references `query_name_w` and `context`, both kept alive
    // in the `BrowseEntry` below for the browse's lifetime.
    let result = unsafe { Dns::DnsServiceBrowse(&request, &mut cancel) };
    if result != DNS_REQUEST_PENDING {
        return Err(format!("DnsServiceBrowse failed with status {result}"));
    }

    let entry = BrowseEntry {
        _cancel: CancelHandle(cancel),
        _context: context,
        _query_name: query_name_w,
    };
    registry
        .lock()
        .map_err(|_| "browse registry poisoned".to_string())?
        .push(entry);
    Ok(())
}

unsafe extern "system" fn browse_callback(
    status: u32,
    context: *const c_void,
    records: *const Dns::DNS_RECORDW,
) {
    // SAFETY: `context` points to the `BrowseContext` owned by the `BrowseEntry`
    // for this browse, which outlives the operation (cancelled before free).
    let ctx = unsafe { &*(context as *const BrowseContext) };

    if status != 0 {
        let _ = ctx.tx.send(Err(ServiceBrowseError::BrowseFailed(format!(
            "browse callback status {status}"
        ))));
    }

    let mut record = records;
    while !record.is_null() {
        // SAFETY: `record` is a node in the system-provided DNS record list.
        let r = unsafe { &*record };
        if r.wType == Dns::DNS_TYPE_PTR.0 {
            let target = trim_dot(&unsafe { pwstr_to_string(r.Data.Ptr.pNameHost) });
            handle_ptr(ctx, target);
        }
        record = r.pNext;
    }

    if !records.is_null() {
        // SAFETY: the record list is owned by us and freed exactly once here.
        unsafe {
            Dns::DnsFree(Some(records as *const c_void), Dns::DnsFreeRecordList);
        }
    }
}

fn handle_ptr(ctx: &BrowseContext, target: String) {
    {
        let mut seen = match ctx.seen.lock() {
            Ok(seen) => seen,
            Err(_) => return,
        };
        if !seen.insert(target.clone()) {
            return; // already handled
        }
    }

    if ctx.is_meta {
        // `target` is a service type, e.g. `_http._tcp.local`. Split off the
        // trailing domain label to recover `(type, domain)` and browse it.
        let (service_type, domain) = match target.rsplit_once('.') {
            Some((service_type, domain)) => (service_type.to_string(), domain.to_string()),
            None => (target.clone(), ctx.domain.clone()),
        };
        trace!("discovered service type {service_type:?} in domain {domain:?}");
        if let Some(registry) = ctx.registry.upgrade() {
            let _ = start_browse(
                target,
                service_type,
                domain,
                ctx.interface,
                false,
                ctx.tx.clone(),
                ctx.handle.clone(),
                &registry,
            );
        }
    } else {
        let label = instance_label(&target, &ctx.service_type, &ctx.domain);
        start_resolve(ctx, target, label);
    }
}

/// Context handed to the resolve completion callback. Owns the query-name
/// backing store for the request's lifetime; reclaimed (and freed) in the
/// callback.
struct ResolveContext {
    tx: BrowseEventSender,
    name: String,
    service_type: String,
    domain: String,
    _query_name: U16CString,
}

fn start_resolve(ctx: &BrowseContext, full_name: String, label: String) {
    let query_name_w = match U16CString::from_str(&full_name) {
        Ok(query_name_w) => query_name_w,
        Err(_) => return,
    };

    let resolve_ctx = Box::new(ResolveContext {
        tx: ctx.tx.clone(),
        name: label,
        service_type: ctx.service_type.clone(),
        domain: ctx.domain.clone(),
        _query_name: query_name_w,
    });
    let query_ptr = resolve_ctx._query_name.as_ptr();
    let resolve_ctx_ptr = Box::into_raw(resolve_ctx);

    let request = Dns::DNS_SERVICE_RESOLVE_REQUEST {
        Version: Dns::DNS_QUERY_REQUEST_VERSION1.0,
        InterfaceIndex: ctx.interface,
        QueryName: PWSTR(query_ptr as *mut u16),
        pResolveCompletionCallback: Some(resolve_callback),
        pQueryContext: resolve_ctx_ptr as *mut c_void,
    };

    let mut cancel = Dns::DNS_SERVICE_CANCEL::default();
    // SAFETY: `request` references the query name owned by the boxed context,
    // which stays alive until the completion callback reclaims it.
    let result = unsafe { Dns::DnsServiceResolve(&request, &mut cancel) };
    if result != DNS_REQUEST_PENDING {
        // The callback will not fire; reclaim the context and report the failure.
        // SAFETY: `resolve_ctx_ptr` came from `Box::into_raw` just above.
        let resolve_ctx = unsafe { Box::from_raw(resolve_ctx_ptr) };
        let _ = resolve_ctx.tx.send(Err(ServiceBrowseError::ResolveFailed(
            resolve_ctx.name.clone(),
            format!("DnsServiceResolve failed with status {result}"),
        )));
    }
    // On success the resolve completes (or times out) on its own; we do not track
    // its cancel handle, so in-flight resolves are simply abandoned on teardown.
}

unsafe extern "system" fn resolve_callback(
    status: u32,
    context: *const c_void,
    instance: *const Dns::DNS_SERVICE_INSTANCE,
) {
    // SAFETY: `context` came from `Box::into_raw` in `start_resolve` and is
    // reclaimed exactly once here.
    let resolve_ctx = unsafe { Box::from_raw(context as *mut ResolveContext) };

    if status != 0 || instance.is_null() {
        let _ = resolve_ctx.tx.send(Err(ServiceBrowseError::ResolveFailed(
            resolve_ctx.name.clone(),
            format!("resolve callback status {status}"),
        )));
        if !instance.is_null() {
            // SAFETY: a non-null instance is owned by us and freed once.
            unsafe { Dns::DnsServiceFreeInstance(instance) };
        }
        return;
    }

    // SAFETY: `instance` is a valid, non-null instance provided by the OS.
    let inst = unsafe { &*instance };

    let mut addresses = Vec::new();
    if !inst.ip4Address.is_null() {
        // SAFETY: non-null per the check above; value is a network-order IPv4.
        let raw = unsafe { *inst.ip4Address };
        addresses.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))));
    }
    if !inst.ip6Address.is_null() {
        // SAFETY: non-null per the check above.
        let bytes = unsafe { (*inst.ip6Address).IP6Byte };
        addresses.push(IpAddr::V6(Ipv6Addr::from(bytes)));
    }

    let txt_records = unsafe { read_txt(inst) };

    let service = DiscoveredService {
        name: resolve_ctx.name.clone(),
        service_type: resolve_ctx.service_type.clone(),
        domain: resolve_ctx.domain.clone(),
        host_name: trim_dot(&unsafe { pwstr_to_string(inst.pszHostName) }),
        port: inst.wPort,
        addresses,
        txt_records,
        interface_index: NonZeroU32::new(inst.dwInterfaceIndex),
    };
    let _ = resolve_ctx.tx.send(Ok(BrowseEvent::Found(service)));

    // SAFETY: the instance is owned by us and freed exactly once.
    unsafe { Dns::DnsServiceFreeInstance(instance) };
}

/// Reads the TXT key/value pairs out of a resolved service instance.
///
/// Windows exposes TXT values as wide strings, so (as with registration) binary
/// TXT values are not representable and are treated as UTF-16 text.
unsafe fn read_txt(inst: &Dns::DNS_SERVICE_INSTANCE) -> Vec<TxtRecord> {
    let count = inst.dwPropertyCount as usize;
    if count == 0 || inst.keys.is_null() {
        return Vec::new();
    }
    // SAFETY: `keys`/`values` are arrays of `count` wide-string pointers.
    let keys = unsafe { std::slice::from_raw_parts(inst.keys, count) };
    let values: &[PWSTR] = if inst.values.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(inst.values, count) }
    };

    let mut records = Vec::with_capacity(count);
    for (i, key_ptr) in keys.iter().enumerate() {
        let key = unsafe { pwstr_to_string(*key_ptr) };
        if key.is_empty() {
            continue;
        }
        let value = match values.get(i) {
            Some(v) if !v.0.is_null() => Some(unsafe { pwstr_to_string(*v) }.into_bytes()),
            _ => None,
        };
        records.push(TxtRecord { key, value });
    }
    records
}

unsafe fn pwstr_to_string(p: PWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    // SAFETY: `p` is a valid, NUL-terminated wide string.
    unsafe { p.to_string() }.unwrap_or_default()
}

/// Returns the instance label of a fully-qualified service name by stripping the
/// trailing `.<service_type>.<domain>` suffix.
fn instance_label(full: &str, service_type: &str, domain: &str) -> String {
    let suffix = format!(".{service_type}.{domain}");
    full.strip_suffix(&suffix).unwrap_or(full).to_string()
}

/// Strips a single trailing `.` (DNS names may be reported fully qualified).
fn trim_dot(s: &str) -> String {
    s.trim_end_matches('.').to_string()
}
