# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/treetop-policy-engine/treetop-client-go/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/treetop-policy-engine/treetop-client-go/releases/tag/v0.0.1
