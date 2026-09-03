# Treetop Go client

An idiomatic Go client for [Treetop REST](https://github.com/treetop-policy-engine/treetop-rest),
the Cedar-based policy authorization service.

The client currently targets the Treetop REST v0.0.15 wire contract. It uses only the Go standard
library.

## Compatibility

| Go client | Treetop REST contract | Minimum Go | Status |
| --- | --- | --- | --- |
| `v0.1.x` | [`v0.0.15`](https://github.com/treetop-policy-engine/treetop-rest/releases/tag/v0.0.15) | 1.23 | Current opaque request-domain API |
| `v0.0.1` | [`v0.0.15`](https://github.com/treetop-policy-engine/treetop-rest/releases/tag/v0.0.15) | 1.23 | Initial API; superseded by `v0.1.x` |

CI tests the minimum Go 1.23 release line and the current stable Go release. The table records the
server wire contract targeted by each client line; server versions not listed are not formally
supported. Some older responses remain decodable where omitted fields have safe defaults, but that
does not constitute a compatibility guarantee.

## Features

- Context-aware methods and typed request/response values.
- Opaque, validated request-domain values that cannot be mutated after construction.
- A concurrency-safe, pooled `http.Client` intended for application-wide reuse.
- Locally validated Cedar identifiers, entity IDs, attributes, IP/CIDR values, request IDs,
  batch uniqueness, and request-context limits.
- Bounded request, successful-response, and error-response buffering.
- Redirect denial and HTTPS requirements for credentials, with explicit danger-prefixed
  development escape hatches.
- Redacted access and upload token formatting and reflected-error redaction.
- Structural authorization-response checks for result order, IDs, counts, policy versions,
  and allow/deny policy consistency.
- A separate `Uploader` capability for policy, schema, and atomic bundle uploads.
- No runtime dependencies outside the Go standard library.

## Installation

```bash
go get github.com/treetop-policy-engine/treetop-client-go
```

The module declares Go 1.23 as its minimum language version.

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"

	treetop "github.com/treetop-policy-engine/treetop-client-go"
)

func main() {
	client, err := treetop.New("https://treetop.example.com")
	if err != nil {
		log.Fatal(err)
	}

	user, err := treetop.NewUser("alice", treetop.UserWithGroupNames("admins"))
	if err != nil {
		log.Fatal(err)
	}
	action, err := treetop.NewAction("view")
	if err != nil {
		log.Fatal(err)
	}
	resourceType, err := treetop.NewEntityType("Document")
	if err != nil {
		log.Fatal(err)
	}
	resource, err := treetop.NewResource(resourceType, "doc-42")
	if err != nil {
		log.Fatal(err)
	}
	request, err := treetop.NewRequest(treetop.UserPrincipal(user), action, resource)
	if err != nil {
		log.Fatal(err)
	}

	allowed, err := client.IsAllowed(context.Background(), request)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Allowed:", allowed)
}
```

## Validated domain values

Request-domain structs have private representations. Construct them with `New...` functions and
inspect them through copying accessors such as `ID`, `Namespace`, `Groups`, `Attributes`, and
`Requests`. JSON decoding uses the same validation boundaries. Most zero request-domain values are
invalid; the two intentional exceptions are the global `Namespace` and an empty
`AuthorizeRequest` batch.

Namespaces and resource entity types are explicit immutable values:

```go
namespace, err := treetop.NewNamespace("MyApp", "Documents")
if err != nil {
	return err
}

documentType, err := treetop.NewEntityType("MyApp::Document")
if err != nil {
	return err
}

user, err := treetop.NewUser("alice", treetop.UserWithNamespace(namespace))
action, err := treetop.NewAction("view", treetop.ActionWithNamespace(namespace))
resource, err := treetop.NewResource(documentType, "doc-42")
```

`Namespace{}` and `NewNamespace()` both represent the global namespace. Use `ParseNamespace` for
an already qualified path such as `MyApp::Documents`. `Segments` returns a copy, so callers cannot
mutate the value. `Namespace.String` returns the qualified `::`-separated path.

## Client configuration

Configuration uses functional options:

```go
accessToken, err := treetop.NewAccessToken("my-access-token")
if err != nil {
	return err
}

client, err := treetop.New(
	"https://treetop.example.com",
	treetop.WithAccessToken(accessToken),
	treetop.WithRequestTimeout(30*time.Second),
	treetop.WithConnectTimeout(5*time.Second),
	treetop.WithMaxRequestBytes(16<<20),
	treetop.WithMaxResponseBytes(16<<20),
)
```

The defaults are a 5-second connect timeout, a 30-second request timeout, a 90-second idle
connection timeout, and 16 MiB request and successful-response limits. Error bodies are always
capped at 64 KiB. Per-call context deadlines may shorten the client timeout.

`WithHTTPClient` reuses a custom transport. The supplied client is copied, standard transports
are cloned before adjustment, and redirects are still denied. This ensures a custom client cannot
forward `Authorization` or `X-Upload-Token` to another origin.

## Authorization batches

```go
first, err := treetop.NewAuthRequest(request, treetop.WithRequestID("check-1"))
if err != nil {
	return err
}

second, err := treetop.NewAuthRequest(
	otherRequest,
	treetop.WithRequestID("check-2"),
	treetop.WithContext(map[string]treetop.AttrValue{
		"environment": treetop.StringValue("production"),
	}),
)
if err != nil {
	return err
}

batch, err := treetop.NewAuthorizeRequest(first, second)
if err != nil {
	return err
}

brief, err := client.Authorize(ctx, batch)
detailed, err := client.AuthorizeDetailed(ctx, batch)
```

Use `FindByID` to correlate a response with a client-provided item ID. The client rejects duplicate
request IDs before transport and validates that the response retains the submitted ordering and IDs.

## Attributes and context

```go
ip, err := treetop.IPValue("10.0.0.0/8")
if err != nil {
	return err
}

hostType, err := treetop.NewEntityType("Host")
if err != nil {
	return err
}

resource, err := treetop.NewResource(
	hostType,
	"web-01.example.com",
	treetop.ResourceWithAttribute("ip", ip),
	treetop.ResourceWithAttribute("critical", treetop.BoolValue(true)),
	treetop.ResourceWithAttribute("priority", treetop.LongValue(1)),
	treetop.ResourceWithAttribute("tags", treetop.SetValue(
		treetop.StringValue("web"),
		treetop.StringValue("production"),
	)),
)
```

The client applies `DefaultRequestLimits` before sending authorization calls. If the target server
has different configured limits, retrieve `Status().RequestLimits` and pass the equivalent values
to `WithRequestLimits` when constructing the long-lived client.

## Uploads

Upload authority is separated from the ordinary client API:

```go
uploadToken, err := treetop.NewUploadToken("my-upload-token")
if err != nil {
	return err
}
uploader, err := client.Uploader(uploadToken)
if err != nil {
	return err
}

metadata, err := uploader.UploadPolicies(
	ctx,
	"permit(principal, action, resource);",
)

metadata, err = uploader.UploadSchema(ctx, schemaJSON)
metadata, err = uploader.UploadBundle(ctx, compressedBundle)
```

`UploadPoliciesJSON` and `UploadSchemaJSON` send the server's string-wrapper JSON forms.
`UploadSchemaDocument` sends an already encoded, unwrapped JSON object. `UploadBundle` sends
`application/gzip` and lets the server verify and apply the archive atomically.

Access and upload tokens require HTTPS unless the host is loopback. Plaintext remote development
requires the separate `DangerouslyAllowInsecureAccessToken` and
`DangerouslyAllowInsecureUploads` options. Token values are redacted when formatted and when a
server reflects them in an API error. Go cannot guarantee zeroization of copies made by the
runtime or HTTP stack; `Destroy` overwrites only the token value's owned byte slice.

## Policy, schema, and operational endpoints

```go
version, err := client.Version(ctx)
status, err := client.Status(ctx)

policies, err := client.Policies(ctx)
cedarText, err := client.PoliciesText(ctx)
schema, err := client.Schema(ctx)
schemaText, err := client.SchemaText(ctx)

policyNamespace, err := treetop.ParseNamespace("MyApp::Documents")
if err != nil {
	return err
}
userPolicies, err := client.UserPolicies(
	ctx,
	"alice",
	treetop.FilterGroups("admins"),
	treetop.FilterNamespaces(policyNamespace),
)

err = client.Live(ctx)
ready, err := client.Ready(ctx)
openapi, err := client.OpenAPI(ctx)
metrics, err := client.Metrics(ctx)
```

`Live`, `Ready`, and `OpenAPI` do not send an access token. `/api/v1/**` and `/metrics` receive the
configured Bearer token. Correlation IDs are sent to both public and protected endpoints.

## Error handling

Errors support the standard `errors.Is` and `errors.As` flow. Important concrete types are
`ValidationError`, `ConfigurationError`, `APIError`, `RequestTooLargeError`,
`ResponseTooLargeError`, `InvalidResponseError`, and `EvaluationError`.

```go
var apiError *treetop.APIError
if errors.As(err, &apiError) {
	fmt.Printf("Treetop returned HTTP %d (%s): %s\n",
		apiError.StatusCode, apiError.Code, apiError.Message)
}
```

See [docs/api.md](docs/api.md) for the endpoint and wire-format reference.

## License

MIT
