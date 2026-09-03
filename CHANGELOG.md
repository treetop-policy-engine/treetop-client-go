# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-03

### Added

- Add `RequestBuilder` and `RequestInput` construction boundaries that return validated `Request`
  values and aggregate independent field failures in `RequestBuildError`.
- Add `UserInGroups` for concise multi-group user construction, with composable membership options.
- Add a digest-pinned Treetop REST v0.0.15 container E2E test covering authenticated status,
  uploads, multi-group authorization, and user-policy listing.
- Add `govulncheck` to CI so reachable dependency and standard-library vulnerabilities fail builds.
- Add authorization request encoding benchmarks for single, medium, and maximum-default batches.

### Changed

- **Breaking:** raise the minimum Go version from 1.23 to 1.25.13 so the client's reachable HTTP,
  TLS, X.509, URL, ASN.1, and PEM paths include current standard-library security fixes. Users must
  upgrade their Go toolchain before adopting this client line.
- **Breaking:** change `NewResource` to accept a qualified entity-type string directly. Callers
  with an existing `EntityType` must use `NewResourceWithType`.
- Make `UserWithGroups`, `UserWithGroupNames`, and `UserInGroups` additive so membership options
  compose in declaration order.
- Match `DefaultRequestLimits` to the server's 1,024-item default batch limit and retain the
  unknown batch limit only when decoding legacy status responses.
- Encode validated authorization requests through plain wire values to avoid repeated nested
  validation and JSON marshaling work, and stream raw string uploads without a `[]byte` copy.
- Preserve caller-supplied HTTP/2 transport preferences and escaped base URL path prefixes.
- Reject all Cedar reserved words in namespace segments and resource entity types.

### Fixed

- Encode empty Cedar sets as JSON arrays and reject missing or null attribute values.
- Require namespace and group arrays when decoding request-domain JSON.
- Reject successful structured responses that omit required Treetop fields or contain inconsistent
  metadata, status, download, or user-policy shapes.
- Extend custom TLS root pools instead of replacing them with the system pool.

### Security

- Redact overlapping access and upload tokens in longest-match order and redact tokens reflected in
  both API error messages and codes.

## [0.1.0] - 2026-09-03

### Added

- Add a versioned compatibility matrix covering the client release line, targeted Treetop REST
  contract, and minimum supported Go version.

### Changed

- **Breaking:** make authorization request-domain values opaque and immutable, introduce validated
  `Namespace` and `EntityType` values, require `EntityType` in `NewResource`, and require
  `Namespace` in namespace options and filters. Callers must use `NewNamespace`, `ParseNamespace`,
  `NewEntityType`, `GroupWithNamespace`, `UserWithNamespace`, `ActionWithNamespace`, and the
  request-domain accessor methods instead of struct fields.
- **Breaking:** make `SingleAuthorizeRequest` return `(*AuthorizeRequest, error)` so invalid zero
  request values cannot bypass construction-time validation.

### Security

- Prevent post-construction mutation of group memberships, resource attributes, authorization
  context, and batch items by returning defensive copies from request-domain accessors.

## [0.0.1] - 2026-09-03

### Added

- Add the initial typed Go client for every Treetop REST v0.0.15 application and operational
  endpoint.
- Add validated authorization request constructors, typed attribute values, brief and detailed
  batch responses, and response consistency checks.
- Add bounded request and response handling, context-aware calls, pooled transport configuration,
  redirect denial, TLS customization, and typed errors.
- Add redacted access and upload tokens, secure-transport enforcement, and a separate `Uploader`
  capability for policy, schema, and atomic bundle uploads.
- Add unit, wire-contract, HTTP hardening, and package example tests.

### Security

- Refuse credentials over remote plaintext HTTP by default, omit access credentials from public
  probes and OpenAPI retrieval, deny redirects, and redact reflected credentials from API errors.

[Unreleased]: https://github.com/treetop-policy-engine/treetop-client-go/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/treetop-policy-engine/treetop-client-go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/treetop-policy-engine/treetop-client-go/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/treetop-policy-engine/treetop-client-go/releases/tag/v0.0.1
