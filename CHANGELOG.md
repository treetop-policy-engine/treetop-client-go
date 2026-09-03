# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/treetop-policy-engine/treetop-client-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/treetop-policy-engine/treetop-client-go/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/treetop-policy-engine/treetop-client-go/releases/tag/v0.0.1
