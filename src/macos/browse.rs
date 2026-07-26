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
/// How often the browse pump wakes to check the stop flag (milliseconds).
const POLL_INTERVAL_MS: i32 = 200;
/// Per-instance resolve timeout (milliseconds).
const RESOLVE_TIMEOUT_MS: i32 = 5000;
/// Per-instance address-lookup budget (milliseconds).
const GETADDR_TIMEOUT_MS: u64 = 2000;

/// Guard returned alongside the event receiver. Dropping it signals the browse
/// pump to stop; within one poll interval it tears down every native browse
/// operation, closes the shared connection to the daemon, and exits.
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

    let pump_stop = stop.clone();
    std::thread::spawn(move || {
        if let Err(err) = run_pump(
            &regtype, &domain, interface, is_meta, &tx, &handle, &pump_stop,
        ) {
            let _ = tx.send(Err(err));
        }
    });

    Ok((rx, BrowseGuard { stop }))
}

/// Resolves a single service instance to a connectable endpoint via
/// `DNSServiceResolve` (+ `DNSServiceGetAddrInfo`). Returns
/// [`ServiceBrowseError::ResolveFailed`] if the instance no longer responds,
/// which callers use as a liveness probe.
///
/// The blocking DNS-SD calls run on a blocking thread so the async caller is
/// not stalled.
pub(crate) async fn resolve_once(
    name: &str,
    service_type: &str,
    domain: &str,
    interface_index: Option<NonZeroU32>,
) -> Result<DiscoveredService, ServiceBrowseError> {
    let interface = interface_index.map(|i| i.get()).unwrap_or(0); // 0 = all interfaces
    let name = name.to_string();
    let service_type = service_type.to_string();
    let domain = domain.to_string();

    tokio::task::spawn_blocking(move || {
        let (host, port, txt_records) = do_resolve(&name, &service_type, &domain, interface)
            .map_err(|err| ServiceBrowseError::ResolveFailed(name.clone(), err))?;
        let addresses = get_addresses(&host, interface).unwrap_or_default();
        Ok(DiscoveredService {
            name,
            service_type: trim_dot(&service_type),
            domain: trim_dot(&domain),
            host_name: trim_dot(&host),
            port,
            addresses,
            txt_records,
            interface_index: NonZeroU32::new(interface),
        })
    })
    .await
    .map_err(|err| {
        ServiceBrowseError::ResolveFailed(String::new(), format!("resolve task failed: {err}"))
    })?
}

/// State shared by every browse operation the pump drives.
///
/// Only ever touched on the pump thread — the callbacks run synchronously inside
/// `DNSServiceProcessResult` — so interior mutability needs no locking.
struct PumpState {
    tx: BrowseEventSender,
    handle: Handle,
    /// Interface scope requested by the caller (0 = all). Used for child browses.
    interface: u32,
    /// `(service_type, domain)` pairs the meta browse has already reported, to
    /// avoid duplicate child browses. The domain is part of the key because the
    /// same type may be advertised in more than one domain.
    seen: RefCell<HashSet<(String, String)>>,
    /// Types the meta browse discovered, waiting for the pump to start a browse
    /// for each. The callback cannot start them itself: it runs inside
    /// `DNSServiceProcessResult`, and starting an operation there would re-enter
    /// the very connection being dispatched on.
    pending: RefCell<Vec<(String, String)>>,
}

/// Callback context for one browse operation: the shared state, plus how to
/// interpret this operation's replies.
///
/// Exactly two of these exist per pump — one for the meta-query and one shared
/// by every per-type instance browse, which needs no per-operation state because
/// each reply carries its own service type and domain.
struct OpContext<'a> {
    state: &'a PumpState,
    is_meta: bool,
}

/// A single connection to the daemon, plus every browse operation started on it.
///
/// `dns_sd.h` documents the ordering this type exists to enforce: deallocating
/// the parent reference implicitly terminates the operations sharing it, and
/// touching them afterwards is a use-after-free. So `Drop` releases the
/// operations first and the connection last.
///
/// Not `Send`: `dns_sd.h` does no internal locking, and deallocating a reference
/// while another thread is inside `DNSServiceProcessResult` on it is the classic
/// crash. Everything here happens on the pump thread.
struct SharedConnection {
    shared: DNSServiceRef,
    ops: Vec<DNSServiceRef>,
}

impl SharedConnection {
    fn create() -> Result<Self, ServiceBrowseError> {
        let mut shared = DNSServiceRef::default();
        let err = unsafe { DNSServiceCreateConnection(&mut shared) };
        if err != error::NO_ERROR {
            return Err(ServiceBrowseError::BrowseFailed(format!(
                "DNSServiceCreateConnection failed: {err}"
            )));
        }
        Ok(Self {
            shared,
            ops: Vec::new(),
        })
    }

    /// The descriptor to poll for all operations on this connection.
    fn socket_fd(&self) -> Result<i32, ServiceBrowseError> {
        let fd = unsafe { DNSServiceRefSockFD(self.shared.0) };
        if fd < 0 {
            return Err(ServiceBrowseError::BrowseFailed(
                "DNSServiceRefSockFD returned an invalid descriptor".into(),
            ));
        }
        Ok(fd)
    }

    /// Reads one queued reply and dispatches it to the owning callback.
    fn process_result(&self) -> Result<(), ServiceBrowseError> {
        let err = unsafe { DNSServiceProcessResult(self.shared.0) };
        if err != error::NO_ERROR {
            return Err(ServiceBrowseError::BrowseFailed(format!(
                "DNSServiceProcessResult failed: {err}"
            )));
        }
        Ok(())
    }

    /// Starts a browse that shares this connection, reporting to `ctx`.
    ///
    /// `ctx` must remain valid until this connection is torn down.
    fn browse(
        &mut self,
        regtype: &str,
        domain: &str,
        interface: u32,
        ctx: *mut c_void,
    ) -> Result<(), ServiceBrowseError> {
        let regtype_c = cstring(regtype)?;
        let domain_c = if domain.is_empty() {
            None // no domain: the daemon uses its default browse domains
        } else {
            Some(cstring(domain)?)
        };

        // Per the `kDNSServiceFlagsShareConnection` contract: copy the parent
        // reference and hand the library the copy, which it initializes in place.
        let mut op = DNSServiceRef(self.shared.0);
        let err = unsafe {
            DNSServiceBrowse(
                &mut op,
                FLAGS_SHARE_CONNECTION,
                interface,
                regtype_c.as_ptr(),
                domain_c.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
                Some(browse_callback),
                ctx,
            )
        };
        if err != error::NO_ERROR {
            return Err(ServiceBrowseError::BrowseFailed(format!(
                "DNSServiceBrowse failed for {regtype}: {err}"
            )));
        }
        self.ops.push(op);
        Ok(())
    }
}

impl Drop for SharedConnection {
    fn drop(&mut self) {
        for op in self.ops.drain(..) {
            // SAFETY: each op came from a successful `DNSServiceBrowse` on this
            // connection and is deallocated exactly once, before the parent.
            unsafe { DNSServiceRefDeallocate(op) };
        }
        // SAFETY: the parent came from a successful `DNSServiceCreateConnection`
        // and is deallocated exactly once, after its operations. No callback can
        // fire after this returns.
        unsafe { DNSServiceRefDeallocate(DNSServiceRef(self.shared.0)) };
    }
}

/// Runs every browse for one [`ServiceBrowser`](crate::ServiceBrowser) on a
/// single thread over a single connection to the daemon.
///
/// The meta-query cascade can fan out to dozens of service types; giving each
/// one its own connection and thread (as this used to) wastes a socket, a thread
/// and a daemon client registration per type. `dns_sd.h` recommends a shared
/// connection for exactly this case.
fn run_pump(
    regtype: &str,
    domain: &str,
    interface: u32,
    is_meta: bool,
    tx: &BrowseEventSender,
    handle: &Handle,
    stop: &Arc<AtomicBool>,
) -> Result<(), ServiceBrowseError> {
    let state = Box::new(PumpState {
        tx: tx.clone(),
        handle: handle.clone(),
        interface,
        seen: RefCell::new(HashSet::new()),
        pending: RefCell::new(Vec::new()),
    });
    // The contexts borrow `state` and are handed to the daemon as raw pointers,
    // so both must outlive `conn` (declared last, dropped first: no callback can
    // fire once its operations are deallocated).
    let meta_ctx = Box::new(OpContext {
        state: &state,
        is_meta: true,
    });
    let instance_ctx = Box::new(OpContext {
        state: &state,
        is_meta: false,
    });
    let meta_ctx_ptr = &*meta_ctx as *const OpContext<'_> as *mut c_void;
    let instance_ctx_ptr = &*instance_ctx as *const OpContext<'_> as *mut c_void;

    let mut conn = SharedConnection::create()?;
    let fd = conn.socket_fd()?;

    let root_ctx = if is_meta {
        meta_ctx_ptr
    } else {
        instance_ctx_ptr
    };
    conn.browse(regtype, domain, interface, root_ctx)?;

    pump_loop(&mut conn, fd, &state, instance_ctx_ptr, stop)
}

/// Polls the shared connection and dispatches replies until the stop flag is
/// set, the daemon hangs up, or an error occurs.
fn pump_loop(
    conn: &mut SharedConnection,
    fd: i32,
    state: &PumpState,
    instance_ctx_ptr: *mut c_void,
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
            conn.process_result()?;
            start_pending_browses(conn, state, instance_ctx_ptr);
        } else if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            break;
        }
    }
    Ok(())
}

/// Starts an instance browse for each service type the meta callback queued.
///
/// A type that cannot be browsed is reported and skipped: one bad type must not
/// take down the browse of every other type sharing this connection.
fn start_pending_browses(
    conn: &mut SharedConnection,
    state: &PumpState,
    instance_ctx_ptr: *mut c_void,
) {
    // Collected first so the borrow is released before starting any browse.
    let pending: Vec<(String, String)> = state.pending.borrow_mut().drain(..).collect();
    for (service_type, domain) in pending {
        if let Err(err) = conn.browse(&service_type, &domain, state.interface, instance_ctx_ptr) {
            let _ = state.tx.send(Err(err));
        }
    }
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
    // SAFETY: `context` points to an `OpContext` owned by the pump thread that
    // issued this operation; it outlives every callback for that operation.
    let ctx = unsafe { &*(context as *const OpContext<'_>) };
    let state = ctx.state;

    if error_code != error::NO_ERROR {
        let _ = state.tx.send(Err(ServiceBrowseError::BrowseFailed(format!(
            "browse callback error: {error_code}"
        ))));
        return;
    }

    let name = unsafe { cstr_to_string(service_name) };
    let regtype = unsafe { cstr_to_string(regtype) };
    let domain = unsafe { cstr_to_string(reply_domain) };
    let is_add = flags & FLAGS_ADD != 0;

    if ctx.is_meta {
        // Meta-query result: the reply is a split-up service type, not an
        // instance. Reconstruct it and queue a per-type instance browse for the
        // pump to start once this dispatch returns.
        if !is_add {
            return; // ignore service-type removals
        }
        let (service_type, child_domain) = meta_reply_to_type_and_domain(&name, &regtype, &domain);
        if state
            .seen
            .borrow_mut()
            .insert((service_type.clone(), child_domain.clone()))
        {
            trace!("discovered service type {service_type:?} in domain {child_domain:?}");
            state
                .pending
                .borrow_mut()
                .push((service_type, child_domain));
        }
    } else if is_add {
        // Resolve off-thread so the pump keeps dispatching. The resolve gets its
        // own connection rather than sharing this one: resolves run concurrently
        // on the blocking pool, and `dns_sd.h` leaves mutual exclusion for a
        // shared reference to the caller (it would also make `MoreComing`
        // collective, which is how the address lookup detects completion).
        let tx = state.tx.clone();
        state
            .handle
            .spawn_blocking(move || resolve_service(name, regtype, domain, interface_index, tx));
    } else {
        let removed = RemovedService {
            name,
            service_type: trim_dot(&regtype),
            domain: trim_dot(&domain),
            interface_index: NonZeroU32::new(interface_index),
        };
        let _ = state.tx.send(Ok(BrowseEvent::Removed(removed)));
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
    if error_code == error::NO_ERROR
        && !address.is_null()
        && let Some(ip) = unsafe { sockaddr_to_ip(address) }
    {
        result.addrs.push(ip);
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

/// Rebuilds the `(service_type, domain)` pair a service-type meta-query reply
/// describes, so it can be fed back into [`DNSServiceBrowse`] as an ordinary
/// per-type browse.
///
/// The meta-query (`_services._dns-sd._udp`) is answered with PTR records whose
/// target is a service type, e.g. `_http._tcp.local.`. mDNSResponder splits that
/// target with `DeconstructServiceName` as if it were a service *instance*
/// name — first label as the instance, the **next two** labels as the type, the
/// remainder as the domain — so the browse callback reports
/// `name = "_http"`, `regtype = "_tcp.local."` and `reply_domain = "."`.
///
/// The reply domain is therefore the DNS root, not the domain the type lives in.
/// Passing it back to `DNSServiceBrowse` asks for the type in the root zone (a
/// unicast query that never reaches mDNS), which is why the domain has to be
/// recovered from `regtype` instead: re-join the three parts and re-split them
/// on the real DNS-SD boundary — the first two labels are the service type and
/// what follows is the domain.
///
/// An empty returned domain means "the default browse domains", which is the
/// right fallback when the reply carried no domain at all.
fn meta_reply_to_type_and_domain(
    name: &str,
    regtype: &str,
    reply_domain: &str,
) -> (String, String) {
    let mut full = format!("{name}.{regtype}");
    // A reply domain of "." (or "") is the root and contributes no labels; any
    // other value is a real suffix that `DeconstructServiceName` split off.
    let suffix = reply_domain.trim_start_matches('.');
    if !suffix.is_empty() {
        if !full.ends_with('.') {
            full.push('.');
        }
        full.push_str(suffix);
    }

    let labels: Vec<&str> = full.trim_end_matches('.').split('.').collect();
    let service_type = labels.iter().take(2).copied().collect::<Vec<_>>().join(".");
    let domain = labels.get(2..).map_or(String::new(), |rest| rest.join("."));
    (service_type, domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape mDNSResponder actually reports for a `local.` service type: the
    /// domain lives in `regtype`, and the reply domain is the DNS root.
    #[test]
    fn meta_reply_recovers_local_domain_from_regtype() {
        let (service_type, domain) = meta_reply_to_type_and_domain("_http", "_tcp.local.", ".");
        assert_eq!(service_type, "_http._tcp");
        assert_eq!(domain, "local");
    }

    /// A root reply domain must never be browsed as if it were a real domain:
    /// that queries the DNS root instead of mDNS and finds nothing.
    #[test]
    fn meta_reply_never_yields_a_root_domain() {
        for reply_domain in [".", "", ".."] {
            let (_, domain) = meta_reply_to_type_and_domain("_ipp", "_tcp.local.", reply_domain);
            assert_eq!(domain, "local", "reply domain {reply_domain:?}");
        }
    }

    #[test]
    fn meta_reply_handles_udp_types() {
        let (service_type, domain) =
            meta_reply_to_type_and_domain("_sleep-proxy", "_udp.local.", ".");
        assert_eq!(service_type, "_sleep-proxy._udp");
        assert_eq!(domain, "local");
    }

    /// A multi-label domain is split across `regtype` and `reply_domain`, because
    /// `DeconstructServiceName` takes exactly two labels for the type: for
    /// `_http._tcp.example.com.` it reports type `_tcp.example.` and domain `com.`.
    #[test]
    fn meta_reply_rejoins_a_multi_label_domain() {
        let (service_type, domain) =
            meta_reply_to_type_and_domain("_http", "_tcp.example.", "com.");
        assert_eq!(service_type, "_http._tcp");
        assert_eq!(domain, "example.com");
    }

    /// Nothing beyond the transport label: browse the default domains rather
    /// than inventing one.
    #[test]
    fn meta_reply_without_a_domain_falls_back_to_the_defaults() {
        let (service_type, domain) = meta_reply_to_type_and_domain("_http", "_tcp.", ".");
        assert_eq!(service_type, "_http._tcp");
        assert_eq!(domain, "");
    }

    /// The reconstructed type is the string handed back to `DNSServiceBrowse`,
    /// so it must survive the `CString` conversion the browse does.
    #[test]
    fn meta_reply_output_is_usable_as_a_browse_type() {
        let (service_type, domain) = meta_reply_to_type_and_domain("_ssh", "_tcp.local.", ".");
        assert_eq!(cstring(&service_type).unwrap().to_bytes(), b"_ssh._tcp");
        assert_eq!(cstring(&domain).unwrap().to_bytes(), b"local");
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
