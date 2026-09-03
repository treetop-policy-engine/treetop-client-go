# Repository Guidelines

These instructions apply to the entire repository. Keep them aligned with the actual package,
commands, CI workflows, and release process whenever those change.

## Priorities

- Preserve the Treetop JSON wire contract and the client's security boundaries.
- Prefer small, explicit, typed APIs over convenience that weakens validation or leaks secrets.
- Keep changes scoped. Do not mix refactors, dependency churn, and behavior changes without a
  concrete reason.
- Preserve Go compatibility declared by `go.mod`; raise it only deliberately and document the
  migration impact.

## Verification

Run the complete local baseline before considering a change complete:

```bash
gofmt -w *.go
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
npx markdownlint-cli2 --config .markdownlint.json "**/*.md"
```

- Review `git diff --check` and the formatted diff after `gofmt`.
- Tests must not require public network services, fixed ports, timing races, or execution order.
  Use `httptest.Server` for HTTP behavior.
- Run `govulncheck ./...` after dependency, transport, parser, authentication, or release changes
  when the tool is available.
- If a required check cannot run in the current environment, run the strongest available subset
  and state exactly what remains unverified.

## Architecture

- `client.go` owns base URL normalization, client lifetime, correlation clones, and credential
  transport checks.
- `options.go` owns functional options and standard HTTP/TLS transport construction.
- `transport.go` owns header application, bounded I/O, JSON decoding, API errors, and redaction.
- `endpoints.go` owns read-only and authorization endpoint methods.
- `uploader.go` owns the upload capability and all credentialed mutation endpoints.
- `request_types.go` and `authorization_request.go` own request-domain values and validation.
- `response_types.go` owns server-facing results, metadata, compatibility defaults, and response
  consistency checks.
- Keep public examples in `example_test.go` so documentation examples compile.

## Go standards

- Follow Effective Go, the Go Code Review Comments, and established package conventions.
- Put `context.Context` first on every blocking or network method. Never store a caller context in a
  client.
- Return concrete typed errors that work with `errors.Is` and `errors.As`; wrap underlying errors
  with `%w`.
- Keep `Client` and `Uploader` safe for concurrent use. Never add mutable request-scoped state to a
  shared client; use clone-with-override or method parameters.
- Reuse `http.Client` and `http.Transport`. Never create a transport per request, and always close
  response bodies.
- Keep interfaces consumer-owned unless the package needs to define a real behavioral boundary.
- Avoid dependencies when the standard library provides an equally safe, clear implementation.
  New dependencies must be maintained, published, license-compatible, and justified.
- Document every exported identifier. Keep zero-value behavior explicit and test constructors plus
  direct-field mutation where exported request structs permit it.

## Wire compatibility

- Treat `../treetop-rest/docs/api.md`, its generated OpenAPI document, server handler tests, and
  released server behavior as sources of truth.
- Preserve JSON field names, enum tags, flattening, omission rules, and query parameter names.
- Assert exact JSON for every changed request shape. A Go round trip alone is not proof of server
  compatibility.
- Preserve unknown string enum values when newer servers may add variants.
- Apply safe defaults only when an omitted older-server field has an unambiguous meaning.
- Validate response counts, indices, IDs, policy versions, decisions, and policy consistency before
  returning authorization results.
- Update `docs/api.md`, README compatibility text, tests, and the changelog when targeting a new
  server contract.

## Security boundaries

- Never expose access or upload tokens in formatting, errors, logs, panic messages, URLs, or test
  failure output.
- Never send a token over non-loopback plaintext HTTP without the matching danger-prefixed opt-in.
- Deny redirects so credentials cannot be forwarded to an unintended origin, including when a
  caller supplies a custom `http.Client`.
- Keep base URLs credential-free and reject unsupported schemes, queries, and fragments.
- Bound successful and error bodies before buffering. Bound outbound bodies before transport.
- Validate HTTP header values, Cedar identifiers, entity IDs, IP addresses/CIDRs, context depth,
  context size, context keys, batch size, and duplicate request IDs at the boundary.
- Avoid panics on network data and other untrusted input. Return typed errors instead.
- Do not claim guaranteed memory zeroization in Go. `Destroy` only overwrites the byte slice owned by
  that token value; runtime and transport copies can remain.

## Tests

- Add a regression test for every bug fix and focused tests for every behavior change.
- Use table-driven tests when one behavior varies only by input.
- Keep network tests on ephemeral loopback listeners via `httptest.Server`.
- Exercise success and failure paths at every boundary, including malformed success responses,
  oversized bodies, redirects, credential omission, redaction, invalid UTF-8, and context limits.
- Use fuzz tests for parsers or deeply nested untrusted data when changing JSON deserialization,
  URL construction, nested attributes, or response consistency.
- Do not weaken validation or assertions merely to make a test pass.

## Documentation and changelog

- Update `docs/api.md` when endpoint behavior, headers, error mapping, or wire shapes change.
- Update README examples and compatibility statements when public usage or the target server changes.
- Review `CHANGELOG.md` for every user-visible change and record it under `[Unreleased]`.
- Call out breaking changes and the required migration action explicitly.
- Give every fenced Markdown block a language; use `text` for plain output.

## Commits and releases

- Keep commits focused and use imperative subjects under 72 characters.
- Sign commits and release tags. Do not bypass configured signing.
- Do not commit test binaries, coverage profiles, local credentials, tool caches, or temporary
  server artifacts.
- Before release, update dependencies and actions deliberately, review upstream security and
  compatibility notes, run the full verification suite plus `govulncheck`, and verify the module
  from a clean checkout.
- Treat pushed tags and published module versions as immutable. Fix a failed release with a new
  commit and version.
