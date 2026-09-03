package treetop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Decision is an authorization outcome.
type Decision string

const (
	DecisionAllow Decision = "Allow"
	DecisionDeny  Decision = "Deny"
)

// PolicyVersion identifies the policy snapshot used for evaluation.
type PolicyVersion struct {
	Hash     string    `json:"hash"`
	LoadedAt time.Time `json:"loaded_at"`
}

func (v PolicyVersion) equal(other PolicyVersion) bool {
	return v.Hash == other.Hash && v.LoadedAt.Equal(other.LoadedAt)
}

// CoreVersion identifies the Treetop core and Cedar engine versions.
type CoreVersion struct {
	Version string `json:"version"`
	Cedar   string `json:"cedar"`
}

// VersionInfo is returned by GET /api/v1/version.
type VersionInfo struct {
	Version  string         `json:"version"`
	Core     CoreVersion    `json:"core"`
	Policies PolicyVersion  `json:"policies"`
	Schema   *PolicyVersion `json:"schema,omitempty"`
}

// PermitPolicy is a matching Cedar permit policy in both text and JSON form.
type PermitPolicy struct {
	Literal      string          `json:"literal"`
	JSON         json.RawMessage `json:"json"`
	AnnotationID *string         `json:"annotation_id,omitempty"`
	CedarID      string          `json:"cedar_id"`
}

// AuthorizeDecisionBrief contains a decision and matching policy IDs.
type AuthorizeDecisionBrief struct {
	Decision Decision      `json:"decision"`
	Version  PolicyVersion `json:"version"`
	PolicyID string        `json:"policy_id"`
}

// AuthorizeDecisionDetailed contains a decision and its matching policies.
type AuthorizeDecisionDetailed struct {
	Policies []PermitPolicy `json:"policy"`
	Decision Decision       `json:"decision"`
	Version  PolicyVersion  `json:"version"`
}

// BatchStatus identifies whether one authorization item evaluated successfully.
type BatchStatus string

const (
	BatchStatusSuccess BatchStatus = "success"
	BatchStatusFailed  BatchStatus = "failed"
)

// BatchResult contains exactly one successful result or evaluation error.
type BatchResult[T any] struct {
	Status BatchStatus `json:"status"`
	Result *T          `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// Succeeded reports whether this item contains a successful evaluation.
func (r BatchResult[T]) Succeeded() bool { return r.Status == BatchStatusSuccess }

// MarshalJSON preserves the server's tagged result shape.
func (r BatchResult[T]) MarshalJSON() ([]byte, error) {
	switch r.Status {
	case BatchStatusSuccess:
		if r.Result == nil || r.Error != "" {
			return nil, &InvalidResponseError{Message: "successful batch result has an invalid payload"}
		}
		return json.Marshal(struct {
			Status BatchStatus `json:"status"`
			Result *T          `json:"result"`
		}{Status: r.Status, Result: r.Result})
	case BatchStatusFailed:
		if r.Result != nil {
			return nil, &InvalidResponseError{Message: "failed batch result contains a successful payload"}
		}
		return json.Marshal(struct {
			Status BatchStatus `json:"status"`
			Error  string      `json:"error"`
		}{Status: r.Status, Error: r.Error})
	default:
		return nil, &InvalidResponseError{Message: fmt.Sprintf("unknown batch result status %q", r.Status)}
	}
}

// UnmarshalJSON validates the tagged result shape while decoding it.
func (r *BatchResult[T]) UnmarshalJSON(data []byte) error {
	var wire struct {
		Status BatchStatus     `json:"status"`
		Result json.RawMessage `json:"result"`
		Error  *string         `json:"error"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	switch wire.Status {
	case BatchStatusSuccess:
		if len(wire.Result) == 0 || bytes.Equal(wire.Result, []byte("null")) || wire.Error != nil {
			return &InvalidResponseError{Message: "successful batch result has an invalid payload"}
		}
		var result T
		if err := json.Unmarshal(wire.Result, &result); err != nil {
			return err
		}
		*r = BatchResult[T]{Status: BatchStatusSuccess, Result: &result}
		return nil
	case BatchStatusFailed:
		if len(wire.Result) != 0 || wire.Error == nil {
			return &InvalidResponseError{Message: "failed batch result has an invalid payload"}
		}
		*r = BatchResult[T]{Status: BatchStatusFailed, Error: *wire.Error}
		return nil
	default:
		return &InvalidResponseError{Message: fmt.Sprintf("unknown batch result status %q", wire.Status)}
	}
}

// IndexedResult is one authorization result in original batch order.
type IndexedResult[T any] struct {
	Index          int     `json:"index"`
	ID             *string `json:"id,omitempty"`
	BatchResult[T] `json:"-"`
}

// MarshalJSON flattens the tagged batch result beside its index and ID.
func (r IndexedResult[T]) MarshalJSON() ([]byte, error) {
	result, err := json.Marshal(r.BatchResult)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result, &fields); err != nil {
		return nil, err
	}
	fields["index"] = json.RawMessage(fmt.Appendf(nil, "%d", r.Index))
	if r.ID != nil {
		id, err := json.Marshal(*r.ID)
		if err != nil {
			return nil, err
		}
		fields["id"] = id
	}
	return json.Marshal(fields)
}

// UnmarshalJSON decodes the flattened indexed result.
func (r *IndexedResult[T]) UnmarshalJSON(data []byte) error {
	var wire struct {
		Index *int    `json:"index"`
		ID    *string `json:"id"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Index == nil {
		return &InvalidResponseError{Message: "authorization result is missing its index"}
	}
	var result BatchResult[T]
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	*r = IndexedResult[T]{Index: *wire.Index, ID: wire.ID, BatchResult: result}
	return nil
}

// AuthorizeResponse is a complete batch result.
type AuthorizeResponse[T any] struct {
	Results    []IndexedResult[T] `json:"results"`
	Version    PolicyVersion      `json:"version"`
	Successful int                `json:"successful"`
	Failed     int                `json:"failed"`
}

// AuthorizeBriefResponse is the brief authorization response form.
type AuthorizeBriefResponse = AuthorizeResponse[AuthorizeDecisionBrief]

// AuthorizeDetailedResponse is the full authorization response form.
type AuthorizeDetailedResponse = AuthorizeResponse[AuthorizeDecisionDetailed]

// FindByID finds the first result with the supplied client request ID.
func (r *AuthorizeResponse[T]) FindByID(id string) (*IndexedResult[T], bool) {
	if r == nil {
		return nil, false
	}
	for i := range r.Results {
		if r.Results[i].ID != nil && *r.Results[i].ID == id {
			return &r.Results[i], true
		}
	}
	return nil, false
}

// Validate checks result count, declared success and failure counts, batch
// order, decisions, policy consistency, and per-result policy versions. Client
// methods additionally validate response IDs against the submitted requests.
func (r *AuthorizeResponse[T]) Validate(expectedResults int) error {
	if expectedResults < 0 {
		return &ValidationError{Field: "expected results", Value: fmt.Sprint(expectedResults), Rule: "must not be negative"}
	}
	return validateAuthorizeResponseStructure(r, expectedResults)
}

func validateAuthorizeResponse[T any](response *AuthorizeResponse[T], request *AuthorizeRequest) error {
	if err := validateAuthorizeResponseStructure(response, len(request.requests)); err != nil {
		return err
	}
	for position := range response.Results {
		item := &response.Results[position]
		expectedID, hasExpectedID := request.requests[position].ID()
		if !hasExpectedID && item.ID != nil || hasExpectedID && (item.ID == nil || *item.ID != expectedID) {
			return &InvalidResponseError{Message: fmt.Sprintf("result index %d has an unexpected request ID", item.Index)}
		}
	}
	return nil
}

func validateAuthorizeResponseStructure[T any](response *AuthorizeResponse[T], expectedResults int) error {
	if response == nil {
		return &InvalidResponseError{Message: "authorize returned a nil response"}
	}
	if len(response.Results) != expectedResults {
		return &InvalidResponseError{Message: fmt.Sprintf("authorize returned %d results for %d requests", len(response.Results), expectedResults)}
	}
	if response.Version.Hash == "" || response.Version.LoadedAt.IsZero() {
		return &InvalidResponseError{Message: "authorize response is missing its policy version"}
	}
	successes := 0
	for position := range response.Results {
		item := &response.Results[position]
		if item.Index != position {
			return &InvalidResponseError{Message: fmt.Sprintf("result at position %d reports index %d", position, item.Index)}
		}
		switch item.Status {
		case BatchStatusSuccess:
			successes++
			if item.Result == nil || item.Error != "" {
				return &InvalidResponseError{Message: fmt.Sprintf("result index %d has an invalid success payload", item.Index)}
			}
			if err := validateDecision(any(*item.Result), response.Version, item.Index); err != nil {
				return err
			}
		case BatchStatusFailed:
			if item.Result != nil {
				return &InvalidResponseError{Message: fmt.Sprintf("result index %d has an invalid failure payload", item.Index)}
			}
		default:
			return &InvalidResponseError{Message: fmt.Sprintf("result index %d has unknown status %q", item.Index, item.Status)}
		}
	}
	failures := len(response.Results) - successes
	if response.Successful != successes || response.Failed != failures {
		return &InvalidResponseError{Message: fmt.Sprintf("declared %d successful and %d failed, observed %d successful and %d failed", response.Successful, response.Failed, successes, failures)}
	}
	return nil
}

func validateDecision(value any, batchVersion PolicyVersion, index int) error {
	switch decision := value.(type) {
	case AuthorizeDecisionBrief:
		if !decision.Version.equal(batchVersion) {
			return versionMismatch(index)
		}
		switch decision.Decision {
		case DecisionAllow:
			if decision.PolicyID == "" {
				return decisionMismatch(index, "Allow decision has no matching policy ID")
			}
		case DecisionDeny:
			if decision.PolicyID != "" {
				return decisionMismatch(index, "Deny decision contains matching policy IDs")
			}
		default:
			return decisionMismatch(index, fmt.Sprintf("unknown decision %q", decision.Decision))
		}
	case AuthorizeDecisionDetailed:
		if !decision.Version.equal(batchVersion) {
			return versionMismatch(index)
		}
		switch decision.Decision {
		case DecisionAllow:
			if len(decision.Policies) == 0 {
				return decisionMismatch(index, "Allow decision has no matching policies")
			}
		case DecisionDeny:
			if len(decision.Policies) != 0 {
				return decisionMismatch(index, "Deny decision contains matching policies")
			}
		default:
			return decisionMismatch(index, fmt.Sprintf("unknown decision %q", decision.Decision))
		}
	default:
		return &InvalidResponseError{Message: fmt.Sprintf("result index %d has an unsupported decision type", index)}
	}
	return nil
}

func versionMismatch(index int) error {
	return &InvalidResponseError{Message: fmt.Sprintf("result index %d reports a different policy version than the batch", index)}
}

func decisionMismatch(index int, message string) error {
	return &InvalidResponseError{Message: fmt.Sprintf("result index %d is inconsistent: %s", index, message)}
}

// MetadataSource identifies the remote URL from which server state was loaded.
// It accepts both the current {"url": "..."} shape and legacy string responses.
type MetadataSource struct {
	URL string `json:"url"`
}

// NewMetadataSource constructs a validated absolute metadata source URL.
func NewMetadataSource(value string) (MetadataSource, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return MetadataSource{}, &ValidationError{Field: "metadata source", Value: value, Rule: "must be an absolute URL"}
	}
	return MetadataSource{URL: value}, nil
}

// UnmarshalJSON supports current and legacy server representations.
func (s *MetadataSource) UnmarshalJSON(data []byte) error {
	var object struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &object); err == nil && object.URL != "" {
		validated, err := NewMetadataSource(object.URL)
		if err != nil {
			return err
		}
		*s = validated
		return nil
	}
	var legacy string
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	validated, err := NewMetadataSource(legacy)
	if err != nil {
		return err
	}
	*s = validated
	return nil
}

// Metadata describes one loaded policy, label, or schema data set.
type Metadata struct {
	Timestamp        time.Time       `json:"timestamp"`
	SHA256           string          `json:"sha256"`
	Size             uint64          `json:"size"`
	Source           *MetadataSource `json:"source,omitempty"`
	RefreshFrequency *uint32         `json:"refresh_frequency,omitempty"`
	Entries          uint64          `json:"entries"`
	Content          string          `json:"content"`
}

// BundleMetadata describes the atomic bundle that produced active policy state.
type BundleMetadata struct {
	FormatVersion    uint32          `json:"format_version"`
	BundleID         string          `json:"bundle_id"`
	ArchiveSHA256    string          `json:"archive_sha256"`
	CompressedSize   uint64          `json:"compressed_size"`
	ModuleCount      uint64          `json:"module_count"`
	Signed           bool            `json:"signed"`
	SigningKeyID     *string         `json:"signing_key_id,omitempty"`
	Source           *MetadataSource `json:"source,omitempty"`
	RefreshFrequency *uint32         `json:"refresh_frequency,omitempty"`
	LoadedAt         time.Time       `json:"loaded_at"`
}

// PoliciesMetadata describes active policy, label, schema, and bundle state.
type PoliciesMetadata struct {
	AllowUpload          bool            `json:"allow_upload"`
	SchemaValidationMode string          `json:"schema_validation_mode"`
	Policies             Metadata        `json:"policies"`
	Labels               Metadata        `json:"labels"`
	Schema               *Metadata       `json:"schema,omitempty"`
	Bundle               *BundleMetadata `json:"bundle,omitempty"`
}

// PoliciesDownload is returned by the structured policy download endpoint.
type PoliciesDownload struct {
	Policies Metadata `json:"policies"`
}

// SchemaDownload is returned by the structured schema download endpoint.
type SchemaDownload struct {
	Schema Metadata `json:"schema"`
}

// RequestLimits are enforced locally for authorization contexts. A zero
// MaxBatchSize means the target server's batch limit is unknown.
type RequestLimits struct {
	MaxBatchSize    int   `json:"max_batch_size,omitempty"`
	MaxContextBytes int64 `json:"max_context_bytes"`
	MaxContextDepth int   `json:"max_context_depth"`
	MaxContextKeys  int   `json:"max_context_keys"`
}

// DefaultRequestLimits returns limits matching the default Treetop server.
func DefaultRequestLimits() RequestLimits {
	return RequestLimits{MaxContextBytes: 16 << 10, MaxContextDepth: 8, MaxContextKeys: 64}
}

func (l RequestLimits) validate() error {
	if l.MaxBatchSize < 0 || l.MaxContextBytes <= 0 || l.MaxContextDepth <= 0 || l.MaxContextKeys <= 0 {
		return &ConfigurationError{Message: "request limits must be positive; max batch size may be zero when unknown"}
	}
	return nil
}

// RequestContextFallbackReason explains why evaluation is not schema-backed.
// Unknown future values are preserved.
type RequestContextFallbackReason string

const (
	FallbackNoSchema           RequestContextFallbackReason = "no_schema"
	FallbackSchemaIncompatible RequestContextFallbackReason = "schema_incompatible"
)

// RequestContextStatus describes the server's context evaluation capability.
type RequestContextStatus struct {
	Supported      bool                          `json:"supported"`
	SchemaBacked   bool                          `json:"schema_backed"`
	FallbackReason *RequestContextFallbackReason `json:"fallback_reason,omitempty"`
}

// ParallelConfiguration reports the current server worker configuration.
type ParallelConfiguration struct {
	CPUCount      uint64 `json:"cpu_count"`
	Workers       uint64 `json:"workers"`
	RayonThreads  uint64 `json:"rayon_threads"`
	ParThreshold  uint64 `json:"par_threshold"`
	AllowParallel bool   `json:"allow_parallel"`
}

// StatusResponse is returned by GET /api/v1/status.
type StatusResponse struct {
	PolicyConfiguration   PoliciesMetadata      `json:"policy_configuration"`
	ParallelConfiguration ParallelConfiguration `json:"parallel_configuration"`
	RequestLimits         RequestLimits         `json:"request_limits"`
	RequestContext        RequestContextStatus  `json:"request_context"`
}

// UnmarshalJSON applies safe legacy defaults for fields omitted by older
// compatible servers.
func (s *StatusResponse) UnmarshalJSON(data []byte) error {
	type plain StatusResponse
	decoded := plain{RequestLimits: DefaultRequestLimits()}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = StatusResponse(decoded)
	return nil
}

// PolicyMatchReason explains why a user-policy query selected a policy.
// Unknown future values are preserved.
type PolicyMatchReason string

const (
	MatchPrincipalEq   PolicyMatchReason = "PrincipalEq"
	MatchPrincipalIn   PolicyMatchReason = "PrincipalIn"
	MatchPrincipalAny  PolicyMatchReason = "PrincipalAny"
	MatchPrincipalIs   PolicyMatchReason = "PrincipalIs"
	MatchPrincipalIsIn PolicyMatchReason = "PrincipalIsIn"
	MatchActionEq      PolicyMatchReason = "ActionEq"
	MatchActionIn      PolicyMatchReason = "ActionIn"
	MatchActionAny     PolicyMatchReason = "ActionAny"
	MatchResourceEq    PolicyMatchReason = "ResourceEq"
	MatchResourceIn    PolicyMatchReason = "ResourceIn"
	MatchResourceAny   PolicyMatchReason = "ResourceAny"
	MatchResourceIs    PolicyMatchReason = "ResourceIs"
	MatchResourceIsIn  PolicyMatchReason = "ResourceIsIn"
)

// PolicyMatch contains the Cedar policy ID and selection reasons.
type PolicyMatch struct {
	CedarID string              `json:"cedar_id"`
	Reasons []PolicyMatchReason `json:"reasons"`
}

// UserPolicies contains policies selected for one user.
type UserPolicies struct {
	User     string            `json:"user"`
	Policies []json.RawMessage `json:"policies"`
	Matches  []PolicyMatch     `json:"matches"`
}
