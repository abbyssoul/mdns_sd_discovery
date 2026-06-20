use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::os::raw::{c_char, c_void};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use log::trace;
use tokio::runtime::Handle;
use tokio::sync::mpsc::unbounded_channel;

use super::ffi::*;
use crate::browse::{
    BrowseEvent, BrowseEventReceiver, BrowseEventSender, DiscoveredService, RemovedService,
    ServiceBrowseError, TxtRecord, parse_txt_buffer, trim_dot,
};

/// The DNS-SD meta-query used to enumerate all service types on the network.
const META_QUERY_TYPE: &str = "_services._dns-sd._udp";
/// How often the browse poll loop wakes to check the stop flag (milliseconds).
const POLL_INTERVAL_MS: i32 = 200;
/// Per-instance resolve timeout (milliseconds).
const RESOLVE_TIMEOUT_MS: i32 = 5000;
/// Per-instance address-lookup budget (milliseconds).
const GETADDR_TIMEOUT_MS: u64 = 2000;

/// Guard returned alongside the event receiver. Dropping it signals every browse
/// thread (root and per-type children) to stop; each tears down its native
/// browse operation and exits within one poll interval.
pub(crate) struct BrowseGuard {
    stop: Arc<AtomicBool>,
}

impl Drop for BrowseGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub(crate) async fn browse_start(
    service_type: &Option<String>,
    domain: &Option<String>,
    interface_index: Option<NonZeroU32>,
) -> Result<(BrowseEventReceiver, BrowseGuard), ServiceBrowseError> {
    let (tx, rx) = unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));
    let handle = Handle::current();
    let interface = interface_index.map(|i| i.get()).unwrap_or(0); // 0 = all interfaces
    let domain = domain.clone().unwrap_or_default();

    let (regtype, is_meta) = match service_type {
        Some(service_type) => (service_type.clone(), false),
        None => (META_QUERY_TYPE.to_string(), true),
    };

    spawn_browse_thread(
        regtype,
        domain,
        interface,
        is_meta,
        tx,
        handle,
        stop.clone(),
    );

    Ok((rx, BrowseGuard { stop }))
}

/// Context handed to the browse callback for the lifetime of one browse thread.
/// Only ever accessed on that thread (the callback runs synchronously inside
/// `DNSServiceProcessResult`), so interior mutability needs no locking.
struct BrowseThreadContext {
    tx: BrowseEventSender,
    handle: Handle,
    stop: Arc<AtomicBool>,
    is_meta: bool,
    /// Interface scope requested by the caller (0 = all). Used for child browses.
    interface: u32,
    /// For meta browses: service types already seen, to avoid duplicate child browses.
    seen: RefCell<HashSet<String>>,
}

fn spawn_browse_thread(
    regtype: String,
    domain: String,
    interface: u32,
    is_meta: bool,
    tx: BrowseEventSender,
    handle: Handle,
    stop: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        if let Err(err) = run_browse(&regtype, &domain, interface, is_meta, &tx, &handle, &stop) {
            let _ = tx.send(Err(err));
        }
    });
}

fn run_browse(
    regtype: &str,
    domain: &str,
    interface: u32,
    is_meta: bool,
    tx: &BrowseEventSender,
    handle: &Handle,
    stop: &Arc<AtomicBool>,
) -> Result<(), ServiceBrowseError> {
    let regtype_c = cstring(regtype)?;
    let domain_c = if domain.is_empty() {
        None
    } else {
        Some(cstring(domain)?)
    };

    let ctx = Box::new(BrowseThreadContext {
        tx: tx.clone(),
        handle: handle.clone(),
        stop: stop.clone(),
        is_meta,
        interface,
        seen: RefCell::new(HashSet::new()),
    });
    let ctx_ptr = &*ctx as *const BrowseThreadContext as *mut c_void;

    let mut sd_ref = DNSServiceRef::default();
    let err = unsafe {
        DNSServiceBrowse(
            &mut sd_ref,
            0,
            interface,
            regtype_c.as_ptr(),
            domain_c.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            Some(browse_callback),
            ctx_ptr,
        )
    };
    if err != error::NO_ERROR {
        return Err(ServiceBrowseError::BrowseFailed(format!(
            "DNSServiceBrowse failed for {regtype}: {err}"
        )));
    }

    let fd = unsafe { DNSServiceRefSockFD(sd_ref.0) };
    if fd < 0 {
        unsafe { DNSServiceRefDeallocate(sd_ref) };
        return Err(ServiceBrowseError::BrowseFailed(
            "DNSServiceRefSockFD returned an invalid descriptor".into(),
        ));
    }

    let result = poll_loop(fd, sd_ref.0, stop);

    unsafe { DNSServiceRefDeallocate(sd_ref) };
    drop(ctx);
    result
}

/// Polls `fd` and dispatches results until the stop flag is set or an error
/// occurs. `ctx` (referenced by the in-flight browse) must outlive this call.
fn poll_loop(
    fd: i32,
    sd: *mut _DNSServiceRef_t,
    stop: &Arc<AtomicBool>,
) -> Result<(), ServiceBrowseError> {
    while !stop.load(Ordering::SeqCst) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rv = unsafe { libc::poll(&mut pfd, 1, POLL_INTERVAL_MS) };
        if rv < 0 {
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(ServiceBrowseError::BrowseFailed(format!(
                "poll failed: {errno}"
            )));
        }
        if rv == 0 {
            continue; // timeout: re-check the stop flag
        }
        if pfd.revents & libc::POLLIN != 0 {
            let perr = unsafe { DNSServiceProcessResult(sd) };
            if perr != error::NO_ERROR {
                return Err(ServiceBrowseError::BrowseFailed(format!(
                    "DNSServiceProcessResult failed: {perr}"
                )));
            }
        } else if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            break;
        }
    }
    Ok(())
}

unsafe extern "C" fn browse_callback(
    _service_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32,
    error_code: DNSServiceErrorType,
    service_name: *const c_char,
    regtype: *const c_char,
    reply_domain: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: `context` points to the `BrowseThreadContext` owned by the browse
    // thread that issued this operation; it outlives all callbacks.
    let ctx = unsafe { &*(context as *const BrowseThreadContext) };

    if error_code != error::NO_ERROR {
        let _ = ctx.tx.send(Err(ServiceBrowseError::BrowseFailed(format!(
            "browse callback error: {error_code}"
        ))));
        return;
    }

    let name = unsafe { cstr_to_string(service_name) };
    let regtype = unsafe { cstr_to_string(regtype) };
    let domain = unsafe { cstr_to_string(reply_domain) };
    let is_add = flags & FLAGS_ADD != 0;

    if ctx.is_meta {
        // Meta-query result: `name` is the service label (e.g. "_http") and
        // `regtype` is the transport + domain (e.g. "_tcp.local."). Reconstruct
        // the full service type and start a per-type instance browse.
        if !is_add {
            return; // ignore service-type removals
        }
        let proto = first_label(&regtype);
        let service_type = format!("{name}.{proto}");
        if ctx.seen.borrow_mut().insert(service_type.clone()) {
            trace!("discovered service type {service_type:?} in domain {domain:?}");
            spawn_browse_thread(
                service_type,
                domain,
                ctx.interface,
                false,
                ctx.tx.clone(),
                ctx.handle.clone(),
                ctx.stop.clone(),
            );
        }
    } else if is_add {
        // Resolve off-thread so the poll loop keeps dispatching.
        let tx = ctx.tx.clone();
        ctx.handle
            .spawn_blocking(move || resolve_service(name, regtype, domain, interface_index, tx));
    } else {
        let removed = RemovedService {
            name,
            service_type: trim_dot(&regtype),
            domain: trim_dot(&domain),
            interface_index: NonZeroU32::new(interface_index),
        };
        let _ = ctx.tx.send(Ok(BrowseEvent::Removed(removed)));
    }
}

/// Resolves a discovered instance to host/port/txt (+addresses) and emits it.
fn resolve_service(
    name: String,
    regtype: String,
    domain: String,
    interface: u32,
    tx: BrowseEventSender,
) {
    let (host, port, txt_records) = match do_resolve(&name, &regtype, &domain, interface) {
        Ok(resolved) => resolved,
        Err(err) => {
            let _ = tx.send(Err(ServiceBrowseError::ResolveFailed(name, err)));
            return;
        }
    };

    let addresses = get_addresses(&host, interface).unwrap_or_default();

    let service = DiscoveredService {
        name,
        service_type: trim_dot(&regtype),
        domain: trim_dot(&domain),
        host_name: trim_dot(&host),
        port,
        addresses,
        txt_records,
        interface_index: NonZeroU32::new(interface),
    };
    let _ = tx.send(Ok(BrowseEvent::Found(service)));
}

#[derive(Default)]
struct ResolveResult {
    host: Option<String>,
    port: u16,
    txt: Vec<TxtRecord>,
    error: DNSServiceErrorType,
    got: bool,
}

fn do_resolve(
    name: &str,
    regtype: &str,
    domain: &str,
    interface: u32,
) -> Result<(String, u16, Vec<TxtRecord>), String> {
    let name_c = cstring(name).map_err(|e| e.to_string())?;
    let regtype_c = cstring(regtype).map_err(|e| e.to_string())?;
    let domain_c = cstring(domain).map_err(|e| e.to_string())?;

    let mut result = ResolveResult::default();
    let mut sd_ref = DNSServiceRef::default();
    let err = unsafe {
        DNSServiceResolve(
            &mut sd_ref,
            0,
            interface,
            name_c.as_ptr(),
            regtype_c.as_ptr(),
            domain_c.as_ptr(),
            Some(resolve_callback),
            &mut result as *mut ResolveResult as *mut c_void,
        )
    };
    if err != error::NO_ERROR {
        return Err(format!("DNSServiceResolve failed: {err}"));
    }

    let fd = unsafe { DNSServiceRefSockFD(sd_ref.0) };
    let processed = process_once(fd, sd_ref.0, RESOLVE_TIMEOUT_MS);
    unsafe { DNSServiceRefDeallocate(sd_ref) };
    processed?;

    if !result.got || result.error != error::NO_ERROR {
        return Err(format!("resolve did not complete (error {})", result.error));
    }
    Ok((result.host.unwrap_or_default(), result.port, result.txt))
}

unsafe extern "C" fn resolve_callback(
    _service_ref: DNSServiceRef,
    _flags: DNSServiceFlags,
    _interface_index: u32,
    error_code: DNSServiceErrorType,
    _fullname: *const c_char,
    host_target: *const c_char,
    port: u16,
    txt_len: u16,
    txt_record: *const u8,
    context: *mut c_void,
) {
    // SAFETY: `context` is the `ResolveResult` owned by the waiting `do_resolve`
    // call, which is blocked in `DNSServiceProcessResult` while this fires.
    let result = unsafe { &mut *(context as *mut ResolveResult) };
    result.got = true;
    result.error = error_code;
    if error_code != error::NO_ERROR {
        return;
    }
    result.host = Some(unsafe { cstr_to_string(host_target) });
    result.port = u16::from_be(port); // port arrives in network byte order
    if !txt_record.is_null() && txt_len > 0 {
        let txt = unsafe { std::slice::from_raw_parts(txt_record, txt_len as usize) };
        result.txt = parse_txt_buffer(txt);
    }
}

#[derive(Default)]
struct AddrResult {
    addrs: Vec<IpAddr>,
    done: bool,
}

fn get_addresses(host: &str, interface: u32) -> Option<Vec<IpAddr>> {
    let host_c = cstring(host).ok()?;
    let mut result = AddrResult::default();
    let mut sd_ref = DNSServiceRef::default();
    let err = unsafe {
        DNSServiceGetAddrInfo(
            &mut sd_ref,
            0,
            interface,
            0, // both IPv4 and IPv6
            host_c.as_ptr(),
            Some(getaddr_callback),
            &mut result as *mut AddrResult as *mut c_void,
        )
    };
    if err != error::NO_ERROR {
        return None;
    }

    let fd = unsafe { DNSServiceRefSockFD(sd_ref.0) };
    let deadline = Instant::now() + Duration::from_millis(GETADDR_TIMEOUT_MS);
    // `result.done` is mutated by `getaddr_callback` via the raw context pointer
    // during `DNSServiceProcessResult`, which clippy cannot see.
    #[allow(clippy::while_immutable_condition)]
    while !result.done {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rv = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as i32) };
        if rv <= 0 {
            break;
        }
        if unsafe { DNSServiceProcessResult(sd_ref.0) } != error::NO_ERROR {
            break;
        }
    }

    unsafe { DNSServiceRefDeallocate(sd_ref) };
    Some(result.addrs)
}

unsafe extern "C" fn getaddr_callback(
    _service_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    _interface_index: u32,
    error_code: DNSServiceErrorType,
    _hostname: *const c_char,
    address: *const libc::sockaddr,
    _ttl: u32,
    context: *mut c_void,
) {
    // SAFETY: `context` is the `AddrResult` owned by the waiting `get_addresses`
    // call, blocked in `DNSServiceProcessResult` while this fires.
    let result = unsafe { &mut *(context as *mut AddrResult) };
    if error_code == error::NO_ERROR && !address.is_null() {
        if let Some(ip) = unsafe { sockaddr_to_ip(address) } {
            result.addrs.push(ip);
        }
    }
    if flags & FLAGS_MORE_COMING == 0 {
        result.done = true;
    }
}

/// Polls `fd` once (up to `timeout_ms`) and processes a single result.
fn process_once(fd: i32, sd: *mut _DNSServiceRef_t, timeout_ms: i32) -> Result<(), String> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rv = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rv < 0 {
        return Err(format!("poll failed: {}", std::io::Error::last_os_error()));
    }
    if rv == 0 {
        return Err("operation timed out".into());
    }
    if unsafe { DNSServiceProcessResult(sd) } != error::NO_ERROR {
        return Err("DNSServiceProcessResult failed".into());
    }
    Ok(())
}

unsafe fn sockaddr_to_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    match unsafe { (*addr).sa_family } as i32 {
        libc::AF_INET => {
            let addr = unsafe { &*(addr as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                addr.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let addr = unsafe { &*(addr as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn cstring(s: &str) -> Result<CString, ServiceBrowseError> {
    CString::new(s.as_bytes()).map_err(|e| {
        ServiceBrowseError::ParameterContainsInteriorNulByte(s.to_string(), e.nul_position())
    })
}

unsafe fn cstr_to_string(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// Returns the first dot-separated label of `s` (e.g. `_tcp.local.` -> `_tcp`).
fn first_label(s: &str) -> &str {
    s.split('.').next().unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_label_returns_leading_segment() {
        assert_eq!(first_label("_tcp.local."), "_tcp");
        assert_eq!(first_label("_udp.example.com"), "_udp");
    }

    #[test]
    fn first_label_without_dot_returns_whole_string() {
        assert_eq!(first_label("_tcp"), "_tcp");
    }

    #[test]
    fn first_label_empty_string() {
        assert_eq!(first_label(""), "");
    }

    #[test]
    fn first_label_leading_dot_yields_empty() {
        assert_eq!(first_label(".local"), "");
    }

    #[test]
    fn cstring_round_trips_plain_ascii() {
        let c = cstring("_http._tcp").unwrap();
        assert_eq!(c.to_bytes(), b"_http._tcp");
    }

    #[test]
    fn cstring_rejects_interior_nul() {
        match cstring("a\0b") {
            Err(ServiceBrowseError::ParameterContainsInteriorNulByte(s, pos)) => {
                assert_eq!(s, "a\0b");
                assert_eq!(pos, 1);
            }
            other => panic!("expected interior nul error, got {other:?}"),
        }
    }

    #[test]
    fn cstr_to_string_null_pointer_is_empty() {
        let s = unsafe { cstr_to_string(std::ptr::null()) };
        assert_eq!(s, "");
    }

    #[test]
    fn cstr_to_string_reads_c_string() {
        let c = CString::new("macbook.local").unwrap();
        let s = unsafe { cstr_to_string(c.as_ptr()) };
        assert_eq!(s, "macbook.local");
    }
}
