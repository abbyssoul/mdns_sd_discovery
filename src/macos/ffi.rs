// This file contains the raw FFI bindings to the macOS DNS-SD API, as defined in
// `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/dns_sd.h`, as
// of version MacOSX26.2.sdk.

pub type DNSServiceFlags = u32;
pub type DNSServiceErrorType = i32;
pub type DNSServiceProtocol = u32;

/// Set in browse/resolve reply flags when the result is an addition (vs removal).
pub const FLAGS_ADD: DNSServiceFlags = 0x2;
/// Set in reply flags when more results are imminent (callback will fire again soon).
///
/// On a shared connection this flag is *collective*: it means more results are
/// queued on the parent reference, not necessarily for the callback that saw it.
pub const FLAGS_MORE_COMING: DNSServiceFlags = 0x1;
/// Passed when starting an operation on a reference copied from one created by
/// [`DNSServiceCreateConnection`], so the library reuses that connection instead
/// of opening a new socket to the daemon.
pub const FLAGS_SHARE_CONNECTION: DNSServiceFlags = 0x4000;

pub mod error {
    pub type ServiceError = i32;

    pub const NO_ERROR: ServiceError = 0;
}

#[repr(C)]
pub struct _DNSServiceRef_t {
    _unused: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(transparent)]
#[derive(Debug, Default)]
pub struct DNSServiceRef(pub(crate) *mut _DNSServiceRef_t);

unsafe impl Send for DNSServiceRef {}

pub type DNSServiceBrowseReply = Option<
    unsafe extern "C" fn(
        service_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        error_code: DNSServiceErrorType,
        service_name: *const ::std::os::raw::c_char,
        regtype: *const ::std::os::raw::c_char,
        reply_domain: *const ::std::os::raw::c_char,
        context: *mut ::std::os::raw::c_void,
    ),
>;

pub type DNSServiceResolveReply = Option<
    unsafe extern "C" fn(
        service_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        error_code: DNSServiceErrorType,
        fullname: *const ::std::os::raw::c_char,
        host_target: *const ::std::os::raw::c_char,
        port: u16, // network byte order
        txt_len: u16,
        txt_record: *const u8,
        context: *mut ::std::os::raw::c_void,
    ),
>;

pub type DNSServiceGetAddrInfoReply = Option<
    unsafe extern "C" fn(
        service_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        error_code: DNSServiceErrorType,
        hostname: *const ::std::os::raw::c_char,
        address: *const libc::sockaddr,
        ttl: u32,
        context: *mut ::std::os::raw::c_void,
    ),
>;

unsafe extern "C" {
    /// Creates a shareable reference: operations started on copies of it (with
    /// [`FLAGS_SHARE_CONNECTION`]) reuse its single socket to the daemon.
    pub unsafe fn DNSServiceCreateConnection(sdRef: *mut DNSServiceRef) -> error::ServiceError;

    pub unsafe fn DNSServiceBrowse(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        regtype: *const ::std::os::raw::c_char,
        domain: *const ::std::os::raw::c_char,
        callBack: DNSServiceBrowseReply,
        context: *mut ::std::os::raw::c_void,
    ) -> error::ServiceError;

    pub unsafe fn DNSServiceResolve(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        name: *const ::std::os::raw::c_char,
        regtype: *const ::std::os::raw::c_char,
        domain: *const ::std::os::raw::c_char,
        callBack: DNSServiceResolveReply,
        context: *mut ::std::os::raw::c_void,
    ) -> error::ServiceError;

    pub unsafe fn DNSServiceGetAddrInfo(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        protocol: DNSServiceProtocol,
        hostname: *const ::std::os::raw::c_char,
        callBack: DNSServiceGetAddrInfoReply,
        context: *mut ::std::os::raw::c_void,
    ) -> error::ServiceError;

    pub unsafe fn DNSServiceRefSockFD(sdRef: *mut _DNSServiceRef_t) -> ::std::os::raw::c_int;

    pub unsafe fn DNSServiceRefDeallocate(sdRef: DNSServiceRef);

    pub unsafe fn DNSServiceProcessResult(sdRef: *mut _DNSServiceRef_t) -> DNSServiceErrorType;
}
