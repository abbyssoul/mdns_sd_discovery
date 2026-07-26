# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **macOS: browsing all service types (the default) found nothing.** The
  service-type meta-query reports the domain inside `regtype` and sets the reply
  domain to the DNS root (`.`); using the latter for the per-type browses asked
  for each type in the root zone, which never reaches mDNS. Browsing an explicit
  `service_type` was unaffected.

### Changed

- macOS: all browse operations for one `ServiceBrowser` now share a single
  connection to `mDNSResponder` and a single thread, instead of one of each per
  service type discovered.

### Added

- `PartialEq`/`Eq` on `TxtRecord`.
- Fuzz targets for the TXT record wire-format helpers (`fuzz/`), with a CI
  soak run, plus security-audit and coverage-reporting workflows.
- `rust-version` (MSRV) declaration and docs.rs builds for the Windows and
  macOS API surface.
- Troubleshooting guide for empty browse results, covering the macOS 15 Local
  Network privacy gate and how to get ground truth from the platform's own
  discovery client.

### Removed

- Unused `network-interface` dev-dependency.

## [0.2.0] - 2026-07-02

### Added

- `ServiceResolverBuilder`: one-shot resolve of a known service instance, for
  liveness re-confirmation of services that stopped announcing themselves.

## [0.1.1] - 2026-06-21

### Added

- Windows (Win32 DNS-SD API) and macOS (DNS-SD framework) backends.

### Changed

- Internal refactoring and deduplication across backends; extra test coverage.

## [0.1.0] - 2026-06-19

### Added

- Initial release: async service browsing over Avahi/D-Bus on Linux.

[Unreleased]: https://github.com/abbyssoul/mdns_sd_discovery/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/abbyssoul/mdns_sd_discovery/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/abbyssoul/mdns_sd_discovery/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/abbyssoul/mdns_sd_discovery/releases/tag/v0.1.0
