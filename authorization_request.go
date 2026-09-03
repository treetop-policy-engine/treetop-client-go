package treetop

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// AuthRequest augments a Request with an optional response-correlation ID and
// request-scoped Cedar context. Its request fields are flattened on the wire.
type AuthRequest struct {
	id      requestID
	context map[string]AttrValue
	request Request
}

// AuthRequestOption configures an AuthRequest.
type AuthRequestOption func(*AuthRequest) error

// WithRequestID attaches an ID which the server returns with this batch item.
func WithRequestID(id string) AuthRequestOption {
	return func(request *AuthRequest) error {
		validated, err := newRequestID(id)
		if err != nil {
			return err
		}
		request.id = validated
		return nil
	}
}

// WithContext attaches request-scoped Cedar values. An empty context is
// omitted from the wire representation.
func WithContext(context map[string]AttrValue) AuthRequestOption {
	return func(request *AuthRequest) error {
		request.context = make(map[string]AttrValue, len(context))
		for name, value := range context {
			if err := validateAttributeName("auth_request.context", name); err != nil {
				return err
			}
			if err := value.Validate(); err != nil {
				return fmt.Errorf("context attribute %q: %w", name, err)
			}
			request.context[name] = value
		}
		return nil
	}
}

// NewAuthRequest constructs a validated batch item.
func NewAuthRequest(request Request, options ...AuthRequestOption) (AuthRequest, error) {
	authRequest := AuthRequest{request: request}
	for _, option := range options {
		if option == nil {
			return AuthRequest{}, &ConfigurationError{Message: "nil authorization request option"}
		}
		if err := option(&authRequest); err != nil {
			return AuthRequest{}, err
		}
	}
	return authRequest, authRequest.Validate()
}

// ID returns the client-provided request ID and whether one is present.
func (r AuthRequest) ID() (string, bool) {
	if !r.id.set {
		return "", false
	}
	return r.id.String(), true
}

// Context returns a copy of the request-scoped Cedar context.
func (r AuthRequest) Context() map[string]AttrValue {
	context := make(map[string]AttrValue, len(r.context))
	for name, value := range r.context {
		context[name] = value
	}
	return context
}

// Request returns the underlying authorization request.
func (r AuthRequest) Request() Request { return r.request }

// Validate checks the request, optional ID, context keys, and context values.
func (r AuthRequest) Validate() error {
	if r.id.set {
		if err := r.id.validate(); err != nil {
			return err
		}
	}
	for name, value := range r.context {
		if err := validateAttributeName("auth_request.context", name); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return fmt.Errorf("context attribute %q: %w", name, err)
		}
	}
	return r.request.Validate()
}

// MarshalJSON flattens Request into the AuthRequest object.
func (r AuthRequest) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	type wire struct {
		ID        string               `json:"id,omitempty"`
		Context   map[string]AttrValue `json:"context,omitempty"`
		Principal Principal            `json:"principal"`
		Action    Action               `json:"action"`
		Resource  Resource             `json:"resource"`
	}
	return json.Marshal(wire{
		ID: r.id.String(), Context: r.context, Principal: r.request.principal,
		Action: r.request.action, Resource: r.request.resource,
	})
}

// UnmarshalJSON decodes and validates the flattened wire representation.
func (r *AuthRequest) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID        *string              `json:"id"`
		Context   map[string]AttrValue `json:"context"`
		Principal Principal            `json:"principal"`
		Action    Action               `json:"action"`
		Resource  Resource             `json:"resource"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	request, err := NewRequest(wire.Principal, wire.Action, wire.Resource)
	if err != nil {
		return err
	}
	options := make([]AuthRequestOption, 0, 2)
	if wire.ID != nil {
		options = append(options, WithRequestID(*wire.ID))
	}
	if len(wire.Context) != 0 {
		options = append(options, WithContext(wire.Context))
	}
	parsed, err := NewAuthRequest(request, options...)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// AuthorizeRequest is a batch of authorization checks.
type AuthorizeRequest struct {
	requests []AuthRequest
}

// MarshalJSON preserves an empty requests array for the Treetop wire contract.
func (r AuthorizeRequest) MarshalJSON() ([]byte, error) {
	requests := r.requests
	if requests == nil {
		requests = []AuthRequest{}
	}
	return json.Marshal(struct {
		Requests []AuthRequest `json:"requests"`
	}{Requests: requests})
}

// UnmarshalJSON requires and validates the requests array.
func (r *AuthorizeRequest) UnmarshalJSON(data []byte) error {
	var wire struct {
		Requests *[]AuthRequest `json:"requests"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Requests == nil {
		return &ValidationError{Field: "authorize request", Rule: "must contain a requests array"}
	}
	r.requests = append([]AuthRequest(nil), (*wire.Requests)...)
	return r.Validate()
}

// NewAuthorizeRequest constructs and validates a batch. Empty batches are
// valid because compatible Treetop servers return an empty response.
func NewAuthorizeRequest(requests ...AuthRequest) (*AuthorizeRequest, error) {
	batch := &AuthorizeRequest{requests: append([]AuthRequest(nil), requests...)}
	if batch.requests == nil {
		batch.requests = []AuthRequest{}
	}
	return batch, batch.Validate()
}

// SingleAuthorizeRequest constructs a one-item authorization batch.
func SingleAuthorizeRequest(request Request) (*AuthorizeRequest, error) {
	item, err := NewAuthRequest(request)
	if err != nil {
		return nil, err
	}
	return NewAuthorizeRequest(item)
}

// RequestsBatch constructs a batch from requests without item IDs or context.
func RequestsBatch(requests ...Request) (*AuthorizeRequest, error) {
	items := make([]AuthRequest, len(requests))
	for i, request := range requests {
		items[i] = AuthRequest{request: request}
	}
	return NewAuthorizeRequest(items...)
}

// Requests returns a copy of the authorization batch items.
func (r *AuthorizeRequest) Requests() []AuthRequest {
	if r == nil {
		return nil
	}
	return append([]AuthRequest(nil), r.requests...)
}

// Len returns the number of authorization checks in the batch.
func (r *AuthorizeRequest) Len() int {
	if r == nil {
		return 0
	}
	return len(r.requests)
}

// Validate checks every request and rejects duplicate item IDs.
func (r *AuthorizeRequest) Validate() error {
	if r == nil {
		return &ValidationError{Field: "authorize request", Rule: "must not be nil"}
	}
	ids := make(map[string]struct{}, len(r.requests))
	for i, request := range r.requests {
		if err := request.Validate(); err != nil {
			return fmt.Errorf("authorize request %d: %w", i, err)
		}
		if !request.id.set {
			continue
		}
		id := request.id.String()
		if _, exists := ids[id]; exists {
			return &ValidationError{Field: "request ID", Value: id, Rule: "is duplicated in the batch"}
		}
		ids[id] = struct{}{}
	}
	return nil
}

func (r *AuthorizeRequest) validateLimits(limits RequestLimits) error {
	if limits.MaxBatchSize > 0 && len(r.requests) > limits.MaxBatchSize {
		return &ValidationError{Field: "authorization batch", Value: fmt.Sprint(len(r.requests)), Rule: fmt.Sprintf("contains more than %d requests", limits.MaxBatchSize)}
	}
	for i, request := range r.requests {
		if len(request.context) == 0 {
			continue
		}
		if len(request.context) > limits.MaxContextKeys {
			return &ValidationError{Field: fmt.Sprintf("requests[%d].context", i), Value: fmt.Sprint(len(request.context)), Rule: fmt.Sprintf("contains more than %d keys", limits.MaxContextKeys)}
		}
		depth := 0
		for _, value := range request.context {
			if current := attrDepth(value); current > depth {
				depth = current
			}
		}
		if depth > limits.MaxContextDepth {
			return &ValidationError{Field: fmt.Sprintf("requests[%d].context", i), Value: fmt.Sprint(depth), Rule: fmt.Sprintf("nesting exceeds depth %d", limits.MaxContextDepth)}
		}
		encoded, err := encodeJSONBounded(toAttrMapWire(request.context), boundedJSONLimit(limits.MaxContextBytes))
		if err != nil {
			var tooLarge *RequestTooLargeError
			if errors.As(err, &tooLarge) {
				return &ValidationError{Field: fmt.Sprintf("requests[%d].context", i), Rule: fmt.Sprintf("exceeds %d bytes", limits.MaxContextBytes)}
			}
			return fmt.Errorf("encode requests[%d].context: %w", i, err)
		}
		encodedBytes := len(encoded) - 1 // json.Encoder.Encode appends one newline.
		if int64(encodedBytes) > limits.MaxContextBytes {
			return &ValidationError{Field: fmt.Sprintf("requests[%d].context", i), Value: fmt.Sprintf("%d bytes", encodedBytes), Rule: fmt.Sprintf("exceeds %d bytes", limits.MaxContextBytes)}
		}
	}
	return nil
}

func boundedJSONLimit(limit int64) int64 {
	if limit < math.MaxInt64 {
		return limit + 1
	}
	return limit
}

func attrDepth(root AttrValue) int {
	type pendingValue struct {
		value AttrValue
		depth int
	}
	maximum := 0
	pending := []pendingValue{{value: root, depth: 1}}
	for len(pending) > 0 {
		last := len(pending) - 1
		current := pending[last]
		pending = pending[:last]
		if current.depth > maximum {
			maximum = current.depth
		}
		if current.value.typeName == AttrTypeSet {
			if values, ok := current.value.value.([]AttrValue); ok {
				for _, value := range values {
					pending = append(pending, pendingValue{value: value, depth: current.depth + 1})
				}
			}
		}
	}
	return maximum
}
