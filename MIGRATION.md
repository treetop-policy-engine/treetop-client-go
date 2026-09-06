# Breaking Go 0.3.0 migration

Upgrade to REST 0.1.0 and Go client 0.3.0 together. Go 1.25.13 remains the minimum.
Early releases prioritize correctness and uniform contracts over compatibility.

## Client API and wire data

Replace `Client.Health(ctx)` with `Client.Live(ctx)` or `Client.Ready(ctx)`.
Schema configuration is always a `Metadata` value in `PoliciesMetadata.Schema`.
`VersionInfo.Schema` remains optional but now holds `SchemaVersion`, with required
`Hash` and `LoadedAt`, separately from policy generations.

Every policy version requires all four fields: hash, load timestamp, nullable
label identifier, and unsigned 64-bit generation. Status requires schema metadata,
request limits, and context capabilities. Metadata sources require `{ "url": ... }`;
bare strings are rejected. Zero batch limits reject nonempty batches. Remove any
caller assumption that missing data or zero means unlimited. Malformed responses
return errors and must never be treated as allow decisions.

## Declared targets and format 2

Label rules in bundles or REST configuration use:

```json
{
  "target": {"resource_type": "App::Host", "attribute": "labels"},
  "field": "name",
  "patterns": [{"name": "prod", "regex": "^prod"}]
}
```

Replace `kind` and `output` with an exact Cedar resource type and attribute.
Duplicate tuples are rejected; distinct types can share attribute names.
Sanitization follows scope, so constrain resource types before trusting labels.
Set source bundle/module manifests to format 2, rebuild archives, and re-sign.
Old archives and syntax are rejected. Upload failures preserve the active state.

CI runs authenticated integration tests against the immutable REST 0.1.0 release
image pinned in its workflow. Release Core, Bundle, and REST before this client.
