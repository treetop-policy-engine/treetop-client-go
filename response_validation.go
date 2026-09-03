package treetop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

type responseValidator interface {
	validateResponse() error
}

func (v PolicyVersion) validateResponse(field string) error {
	if v.Hash == "" || v.LoadedAt.IsZero() {
		return invalidResponse(field + " is missing its hash or load timestamp")
	}
	return nil
}

func (v *VersionInfo) validateResponse() error {
	if v == nil || v.Version == "" || v.Core.Version == "" || v.Core.Cedar == "" {
		return invalidResponse("version response is missing required version fields")
	}
	if err := v.Policies.validateResponse("version policies"); err != nil {
		return err
	}
	if v.Schema != nil {
		return v.Schema.validateResponse("version schema")
	}
	return nil
}

// UnmarshalJSON requires every field mandated by the v0.0.15 version response.
func (v *VersionInfo) UnmarshalJSON(data []byte) error {
	var wire struct {
		Version  *string        `json:"version"`
		Core     *CoreVersion   `json:"core"`
		Policies *PolicyVersion `json:"policies"`
		Schema   *PolicyVersion `json:"schema"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Version == nil || wire.Core == nil || wire.Policies == nil {
		return invalidResponse("version response is missing required fields")
	}
	*v = VersionInfo{Version: *wire.Version, Core: *wire.Core, Policies: *wire.Policies, Schema: wire.Schema}
	return v.validateResponse()
}

func (p PermitPolicy) validateResponse(index int) error {
	var policyObject map[string]json.RawMessage
	if p.Literal == "" || p.CedarID == "" || json.Unmarshal(p.JSON, &policyObject) != nil || policyObject == nil {
		return invalidResponse(fmt.Sprintf("matching policy %d is incomplete", index))
	}
	return nil
}

// UnmarshalJSON requires the complete brief decision shape, including an empty
// policy_id for Deny decisions.
func (d *AuthorizeDecisionBrief) UnmarshalJSON(data []byte) error {
	var wire struct {
		Decision *Decision      `json:"decision"`
		Version  *PolicyVersion `json:"version"`
		PolicyID *string        `json:"policy_id"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Decision == nil || wire.Version == nil || wire.PolicyID == nil {
		return invalidResponse("brief authorization decision is missing required fields")
	}
	*d = AuthorizeDecisionBrief{Decision: *wire.Decision, Version: *wire.Version, PolicyID: *wire.PolicyID}
	return nil
}

// UnmarshalJSON requires the policy array even when a Deny decision has no
// matching policies.
func (d *AuthorizeDecisionDetailed) UnmarshalJSON(data []byte) error {
	var wire struct {
		Policies *[]PermitPolicy `json:"policy"`
		Decision *Decision       `json:"decision"`
		Version  *PolicyVersion  `json:"version"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Policies == nil || wire.Decision == nil || wire.Version == nil {
		return invalidResponse("detailed authorization decision is missing required fields")
	}
	*d = AuthorizeDecisionDetailed{Policies: *wire.Policies, Decision: *wire.Decision, Version: *wire.Version}
	return nil
}

// UnmarshalJSON requires all top-level batch fields, including a present empty
// results array.
func (r *AuthorizeResponse[T]) UnmarshalJSON(data []byte) error {
	var wire struct {
		Results    *[]IndexedResult[T] `json:"results"`
		Version    *PolicyVersion      `json:"version"`
		Successful *int                `json:"successful"`
		Failed     *int                `json:"failed"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Results == nil || wire.Version == nil || wire.Successful == nil || wire.Failed == nil {
		return invalidResponse("authorization response is missing required fields")
	}
	*r = AuthorizeResponse[T]{Results: *wire.Results, Version: *wire.Version, Successful: *wire.Successful, Failed: *wire.Failed}
	return nil
}

// UnmarshalJSON requires all metadata fields mandated by the server contract.
func (m *Metadata) UnmarshalJSON(data []byte) error {
	var wire struct {
		Timestamp        *time.Time      `json:"timestamp"`
		SHA256           *string         `json:"sha256"`
		Size             *uint64         `json:"size"`
		Source           *MetadataSource `json:"source"`
		RefreshFrequency *uint32         `json:"refresh_frequency"`
		Entries          *uint64         `json:"entries"`
		Content          *string         `json:"content"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Timestamp == nil || wire.SHA256 == nil || wire.Size == nil || wire.Entries == nil || wire.Content == nil {
		return invalidResponse("metadata is missing required fields")
	}
	*m = Metadata{
		Timestamp: *wire.Timestamp, SHA256: *wire.SHA256, Size: *wire.Size,
		Source: wire.Source, RefreshFrequency: wire.RefreshFrequency,
		Entries: *wire.Entries, Content: *wire.Content,
	}
	return m.validateResponse("metadata")
}

func (m Metadata) validateResponse(field string) error {
	if m.Timestamp.IsZero() {
		return invalidResponse(field + " is missing its timestamp")
	}
	return nil
}

// UnmarshalJSON requires the complete bundle metadata shape.
func (b *BundleMetadata) UnmarshalJSON(data []byte) error {
	var wire struct {
		FormatVersion    *uint32         `json:"format_version"`
		BundleID         *string         `json:"bundle_id"`
		ArchiveSHA256    *string         `json:"archive_sha256"`
		CompressedSize   *uint64         `json:"compressed_size"`
		ModuleCount      *uint64         `json:"module_count"`
		Signed           *bool           `json:"signed"`
		SigningKeyID     *string         `json:"signing_key_id"`
		Source           *MetadataSource `json:"source"`
		RefreshFrequency *uint32         `json:"refresh_frequency"`
		LoadedAt         *time.Time      `json:"loaded_at"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.FormatVersion == nil || wire.BundleID == nil || wire.ArchiveSHA256 == nil || wire.CompressedSize == nil || wire.ModuleCount == nil || wire.Signed == nil || wire.LoadedAt == nil {
		return invalidResponse("bundle metadata is missing required fields")
	}
	*b = BundleMetadata{
		FormatVersion: *wire.FormatVersion, BundleID: *wire.BundleID, ArchiveSHA256: *wire.ArchiveSHA256,
		CompressedSize: *wire.CompressedSize, ModuleCount: *wire.ModuleCount, Signed: *wire.Signed,
		SigningKeyID: wire.SigningKeyID, Source: wire.Source, RefreshFrequency: wire.RefreshFrequency,
		LoadedAt: *wire.LoadedAt,
	}
	return b.validateResponse()
}

func (b BundleMetadata) validateResponse() error {
	if b.FormatVersion == 0 || b.BundleID == "" || b.ArchiveSHA256 == "" || b.LoadedAt.IsZero() {
		return invalidResponse("bundle metadata contains invalid required fields")
	}
	if b.Signed && (b.SigningKeyID == nil || *b.SigningKeyID == "") {
		return invalidResponse("signed bundle metadata is missing its signing key ID")
	}
	if !b.Signed && b.SigningKeyID != nil {
		return invalidResponse("unsigned bundle metadata contains a signing key ID")
	}
	return nil
}

// UnmarshalJSON requires the current PoliciesMetadata shape. In v0.0.15 the
// schema metadata object is present even when its content is empty.
func (p *PoliciesMetadata) UnmarshalJSON(data []byte) error {
	var wire struct {
		AllowUpload          *bool           `json:"allow_upload"`
		SchemaValidationMode *string         `json:"schema_validation_mode"`
		Policies             *Metadata       `json:"policies"`
		Labels               *Metadata       `json:"labels"`
		Schema               *Metadata       `json:"schema"`
		Bundle               *BundleMetadata `json:"bundle"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.AllowUpload == nil || wire.SchemaValidationMode == nil || wire.Policies == nil || wire.Labels == nil || wire.Schema == nil {
		return invalidResponse("policy metadata is missing required fields")
	}
	*p = PoliciesMetadata{
		AllowUpload: *wire.AllowUpload, SchemaValidationMode: *wire.SchemaValidationMode,
		Policies: *wire.Policies, Labels: *wire.Labels, Schema: wire.Schema, Bundle: wire.Bundle,
	}
	return p.validateResponse()
}

func (p *PoliciesMetadata) validateResponse() error {
	if p == nil || p.SchemaValidationMode == "" || p.Schema == nil {
		return invalidResponse("policy metadata is incomplete")
	}
	if err := p.Policies.validateResponse("policies metadata"); err != nil {
		return err
	}
	if err := p.Labels.validateResponse("labels metadata"); err != nil {
		return err
	}
	if err := p.Schema.validateResponse("schema metadata"); err != nil {
		return err
	}
	if p.Bundle != nil {
		return p.Bundle.validateResponse()
	}
	return nil
}

// UnmarshalJSON requires every runtime configuration field.
func (p *ParallelConfiguration) UnmarshalJSON(data []byte) error {
	var wire struct {
		CPUCount      *uint64 `json:"cpu_count"`
		Workers       *uint64 `json:"workers"`
		RayonThreads  *uint64 `json:"rayon_threads"`
		ParThreshold  *uint64 `json:"par_threshold"`
		AllowParallel *bool   `json:"allow_parallel"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.CPUCount == nil || wire.Workers == nil || wire.RayonThreads == nil || wire.ParThreshold == nil || wire.AllowParallel == nil {
		return invalidResponse("parallel configuration is missing required fields")
	}
	*p = ParallelConfiguration{
		CPUCount: *wire.CPUCount, Workers: *wire.Workers, RayonThreads: *wire.RayonThreads,
		ParThreshold: *wire.ParThreshold, AllowParallel: *wire.AllowParallel,
	}
	return nil
}

// UnmarshalJSON requires supported and schema_backed when the current server
// includes request-context status.
func (s *RequestContextStatus) UnmarshalJSON(data []byte) error {
	var wire struct {
		Supported      *bool                         `json:"supported"`
		SchemaBacked   *bool                         `json:"schema_backed"`
		FallbackReason *RequestContextFallbackReason `json:"fallback_reason"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Supported == nil || wire.SchemaBacked == nil {
		return invalidResponse("request-context status is missing required fields")
	}
	*s = RequestContextStatus{Supported: *wire.Supported, SchemaBacked: *wire.SchemaBacked, FallbackReason: wire.FallbackReason}
	return s.validateResponse()
}

func (s RequestContextStatus) validateResponse() error {
	if !s.Supported && (s.SchemaBacked || s.FallbackReason != nil) {
		return invalidResponse("unsupported request context has runtime capability fields")
	}
	if s.SchemaBacked && (!s.Supported || s.FallbackReason != nil) {
		return invalidResponse("schema-backed request context has inconsistent fields")
	}
	if s.Supported && !s.SchemaBacked && s.FallbackReason == nil {
		return invalidResponse("request-context fallback is missing its reason")
	}
	return nil
}

func unmarshalStatusResponse(data []byte, status *StatusResponse) error {
	var wire struct {
		PolicyConfiguration   *PoliciesMetadata      `json:"policy_configuration"`
		ParallelConfiguration *ParallelConfiguration `json:"parallel_configuration"`
		RequestLimits         json.RawMessage        `json:"request_limits"`
		RequestContext        json.RawMessage        `json:"request_context"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.PolicyConfiguration == nil || wire.ParallelConfiguration == nil {
		return invalidResponse("status response is missing required configuration fields")
	}
	limits := legacyRequestLimits()
	if len(wire.RequestLimits) != 0 {
		if bytes.Equal(bytes.TrimSpace(wire.RequestLimits), []byte("null")) {
			return invalidResponse("status request limits must not be null")
		}
		var err error
		limits, err = decodeRequestLimits(wire.RequestLimits)
		if err != nil {
			return err
		}
	}
	if err := limits.validateResponse(); err != nil {
		return err
	}
	requestContext := RequestContextStatus{}
	if len(wire.RequestContext) != 0 {
		if bytes.Equal(bytes.TrimSpace(wire.RequestContext), []byte("null")) {
			return invalidResponse("status request context must not be null")
		}
		if err := json.Unmarshal(wire.RequestContext, &requestContext); err != nil {
			return err
		}
	}
	*status = StatusResponse{
		PolicyConfiguration:   *wire.PolicyConfiguration,
		ParallelConfiguration: *wire.ParallelConfiguration,
		RequestLimits:         limits, RequestContext: requestContext,
	}
	return status.validateResponse()
}

func decodeRequestLimits(data []byte) (RequestLimits, error) {
	var wire struct {
		MaxBatchSize    *int   `json:"max_batch_size"`
		MaxContextBytes *int64 `json:"max_context_bytes"`
		MaxContextDepth *int   `json:"max_context_depth"`
		MaxContextKeys  *int   `json:"max_context_keys"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return RequestLimits{}, err
	}
	if wire.MaxContextBytes == nil || wire.MaxContextDepth == nil || wire.MaxContextKeys == nil {
		return RequestLimits{}, invalidResponse("status request limits are missing required fields")
	}
	limits := RequestLimits{
		MaxContextBytes: *wire.MaxContextBytes,
		MaxContextDepth: *wire.MaxContextDepth,
		MaxContextKeys:  *wire.MaxContextKeys,
	}
	if wire.MaxBatchSize != nil {
		limits.MaxBatchSize = *wire.MaxBatchSize
	}
	return limits, nil
}

func (l RequestLimits) validateResponse() error {
	if l.MaxBatchSize < 0 || l.MaxContextBytes <= 0 || l.MaxContextDepth <= 0 || l.MaxContextKeys <= 0 {
		return invalidResponse("status request limits are invalid")
	}
	return nil
}

func (s *StatusResponse) validateResponse() error {
	if s == nil {
		return invalidResponse("status response is nil")
	}
	if err := s.PolicyConfiguration.validateResponse(); err != nil {
		return err
	}
	if err := s.RequestLimits.validateResponse(); err != nil {
		return err
	}
	return s.RequestContext.validateResponse()
}

// UnmarshalJSON requires the structured policy-download wrapper.
func (p *PoliciesDownload) UnmarshalJSON(data []byte) error {
	var wire struct {
		Policies *Metadata `json:"policies"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Policies == nil {
		return invalidResponse("policy download is missing policies metadata")
	}
	p.Policies = *wire.Policies
	return p.validateResponse()
}

func (p *PoliciesDownload) validateResponse() error {
	if p == nil {
		return invalidResponse("policy download is nil")
	}
	return p.Policies.validateResponse("policy download")
}

// UnmarshalJSON requires the structured schema-download wrapper.
func (s *SchemaDownload) UnmarshalJSON(data []byte) error {
	var wire struct {
		Schema *Metadata `json:"schema"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Schema == nil {
		return invalidResponse("schema download is missing schema metadata")
	}
	s.Schema = *wire.Schema
	return s.validateResponse()
}

func (s *SchemaDownload) validateResponse() error {
	if s == nil {
		return invalidResponse("schema download is nil")
	}
	return s.Schema.validateResponse("schema download")
}

// UnmarshalJSON requires all user-policy collection fields.
func (u *UserPolicies) UnmarshalJSON(data []byte) error {
	var wire struct {
		User     *string            `json:"user"`
		Policies *[]json.RawMessage `json:"policies"`
		Matches  *[]PolicyMatch     `json:"matches"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.User == nil || wire.Policies == nil || wire.Matches == nil {
		return invalidResponse("user-policy response is missing required fields")
	}
	*u = UserPolicies{User: *wire.User, Policies: *wire.Policies, Matches: *wire.Matches}
	return u.validateResponse()
}

func (u *UserPolicies) validateResponse() error {
	if u == nil || u.User == "" || u.Policies == nil || u.Matches == nil || len(u.Policies) != len(u.Matches) {
		return invalidResponse("user-policy response is inconsistent")
	}
	for i, policy := range u.Policies {
		var object map[string]json.RawMessage
		if json.Unmarshal(policy, &object) != nil || object == nil {
			return invalidResponse(fmt.Sprintf("user policy %d is not a JSON object", i))
		}
		if u.Matches[i].CedarID == "" || len(u.Matches[i].Reasons) == 0 {
			return invalidResponse(fmt.Sprintf("user policy match %d is incomplete", i))
		}
	}
	return nil
}

func invalidResponse(message string) error {
	return &InvalidResponseError{Message: message}
}
