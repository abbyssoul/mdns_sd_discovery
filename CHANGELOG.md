# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `PartialEq`/`Eq` on `TxtRecord`.
- Fuzz targets for the TXT record wire-format helpers (`fuzz/`), with a CI
  soak run, plus security-audit and coverage-reporting workflows.
- `rust-version` (MSRV) declaration and docs.rs builds for the Windows and
  macOS API surface.

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
