# API and wire reference

Treetop application endpoints are rooted at `/api/v1`. Operational endpoints are relative to the
configured base URL path.

## Endpoint mapping

| Method | Path | Go method | Result |
| --- | --- | --- | --- |
| GET | `/livez` | `Client.Live` | error only |
| GET | `/readyz` | `Client.Ready` | bool; 503 maps to false |
| GET | `/openapi.json` | `Client.OpenAPI` | validated `json.RawMessage` |
| GET | `/api/v1/health` | `Client.Health` | error only |
| GET | `/api/v1/version` | `Client.Version` | `VersionInfo` |
| GET | `/api/v1/status` | `Client.Status` | `StatusResponse` |
| POST | `/api/v1/authorize?detail=brief` | `Client.Authorize` | `AuthorizeBriefResponse` |
| POST | `/api/v1/authorize?detail=full` | `Client.AuthorizeDetailed` | `AuthorizeDetailedResponse` |
| GET | `/api/v1/policies` | `Client.Policies` | `PoliciesDownload` |
| GET | `/api/v1/policies?format=raw` | `Client.PoliciesText` | string |
| POST | `/api/v1/policies` | `Uploader.UploadPolicies*` | `PoliciesMetadata` |
| POST | `/api/v1/bundle` | `Uploader.UploadBundle` | `PoliciesMetadata` |
| GET | `/api/v1/schema` | `Client.Schema` | `SchemaDownload` |
| GET | `/api/v1/schema?format=raw` | `Client.SchemaText` | string |
| POST | `/api/v1/schema` | `Uploader.UploadSchema*` | `PoliciesMetadata` |
| GET | `/api/v1/policies/{user}` | `Client.UserPolicies` | `UserPolicies` |
| GET | `/api/v1/policies/{user}?format=raw` | `Client.UserPoliciesText` | string |
| GET | `/metrics` | `Client.Metrics` | string |

All methods take `context.Context` first. `Client` and `Uploader` are safe for concurrent use.

## Headers and credential boundaries

| Header | Sent to | Source |
| --- | --- | --- |
| `Authorization: Bearer ...` | `/api/v1/**` and `/metrics` | `WithAccessToken` |
| `X-Upload-Token` | policy, schema, and bundle POSTs | `Client.Uploader` |
| `x-correlation-id` | every request | `WithCorrelationID` or clone override |
| `User-Agent` | every request | default or `WithUserAgent` |

The default and custom-client paths deny redirects. Tokens are refused over non-loopback HTTP
unless the corresponding danger-prefixed option is supplied.

## Authorization request

`Principal` uses an externally tagged `User` or `Group` object. An `AuthRequest` flattens the
principal, action, and resource fields beside its optional ID and context:

```json
{
  "requests": [
    {
      "id": "check-1",
      "context": {
        "env": { "type": "String", "value": "prod" }
      },
      "principal": {
        "User": {
          "id": "alice",
          "namespace": ["MyApp"],
          "groups": [{ "id": "admins", "namespace": [] }]
        }
      },
      "action": { "id": "view", "namespace": [] },
      "resource": {
        "kind": "Document",
        "id": "doc-42",
        "attrs": {
          "owner": { "type": "String", "value": "alice" }
        }
      }
    }
  ]
}
```

Attribute values use adjacent `type` and `value` tags:

| Type | Go constructor | JSON value |
| --- | --- | --- |
| `String` | `StringValue` | string |
| `Bool` | `BoolValue` | boolean |
| `Long` | `LongValue` | signed 64-bit integer |
| `Ip` | `IPValue` | validated IP address or CIDR string |
| `Set` | `SetValue` | nested array of attribute values |

The constructor APIs validate immediately. Exported request fields are validated again before
transport so mutation cannot bypass safety checks.

## Authorization response

Brief responses contain one ordered result per submitted request:

```json
{
  "results": [
    {
      "index": 0,
      "id": "check-1",
      "status": "success",
      "result": {
        "decision": "Allow",
        "policy_id": "policy0",
        "version": {
          "hash": "c82d1168...",
          "loaded_at": "2026-09-03T07:00:00Z"
        }
      }
    }
  ],
  "version": {
    "hash": "c82d1168...",
    "loaded_at": "2026-09-03T07:00:00Z"
  },
  "successful": 1,
  "failed": 0
}
```

A failed item uses `{"status":"failed","error":"..."}`. Detailed success results replace
`policy_id` with a `policy` array of `PermitPolicy` values. The client verifies counts, positions,
IDs, per-result policy versions, known decisions, and matching-policy consistency before returning
either response form.

## User-policy query

`FilterNamespaces` emits repeated `namespaces[]` query values and validates qualified Cedar paths.
`FilterGroups` emits repeated `groups[]` values. The user ID is encoded as exactly one URL path
segment, including spaces and slashes.

## Metadata and compatibility

`MetadataSource` decodes the current `{"url":"https://..."}` form and the legacy bare string form.
Unknown `PolicyMatchReason` and `RequestContextFallbackReason` string values remain accessible for
forward compatibility. Missing legacy status limits default to 16 KiB, depth 8, and 64 keys;
missing context capability defaults to unsupported. `PoliciesMetadata.Bundle` carries v0.0.15
atomic-bundle metadata when present.

## Errors and limits

Current server errors have this shape; older responses containing only `error` are also accepted:

```json
{
  "error": "Human-readable message",
  "code": "machine_readable_code",
  "details": { "line": 3, "column": 9 }
}
```

Non-2xx responses become `APIError`. The successful body limit defaults to 16 MiB and the error
body limit is fixed at 64 KiB. JSON and raw request bodies default to 16 MiB. Plain-text responses
must be valid UTF-8. An oversized or structurally inconsistent response is never returned as a
successful result.
