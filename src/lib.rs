#![warn(missing_docs)]
#![warn(unused_extern_crates, unused_qualifications)]

//! Access the operating system's built-in
//! [DNS-SD](https://en.wikipedia.org/wiki/Zero-configuration_networking#DNS-based_service_discovery) /
//! [mDNS](https://en.wikipedia.org/wiki/Multicast_DNS) stack for service
//! discovery.
//!
//! This crate provides a cross-platform async API (using [Tokio](https://tokio.rs)) for
//! browsing DNS-SD services via the native OS facilities:
//!
//! - **macOS**: native [DNS-SD framework](https://developer.apple.com/documentation/dnssd) (available since macOS 10.12)
//! - **Windows**: native [Win32 DNS-SD API](https://learn.microsoft.com/en-us/uwp/api/windows.networking.servicediscovery.dnssd?view=winrt-28000) (available since Windows 10)
//! - **Linux/FreeBSD**: [Avahi](https://avahi.org) via D-Bus (no binary dependency on libavahi)
//!
//! Service registration lives in a separate crate.
//!
//! # Discovery
//!
//! By default a [`ServiceBrowser`] discovers every service type on the network.
//! Filter on [`DiscoveredService::service_type`], or narrow to a single type
//! with [`ServiceBrowserBuilder::service_type`].
//!
//! ```no_run
//! use mdns_sd_discovery::{BrowseEvent, ServiceBrowserBuilder};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut browser = ServiceBrowserBuilder::new().browse().await?;
//!
//! while let Some(event) = browser.recv().await {
//!     match event? {
//!         BrowseEvent::Found(svc) => {
//!             println!("+ [{}] {} at {}:{}", svc.service_type, svc.name, svc.host_name, svc.port);
//!         }
//!         BrowseEvent::Removed(svc) => println!("- [{}] {}", svc.service_type, svc.name),
//!     }
//! }
//! // Dropping `browser` stops the browse.
//! # Ok(())
//! # }
//! ```

pub use self::browse::*;

mod browse;

#[cfg(all(unix, not(target_os = "macos")))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
