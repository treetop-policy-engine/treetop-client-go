package treetop

import (
	"encoding/json"
	"fmt"
)

// AuthRequest augments a Request with an optional response-correlation ID and
// request-scoped Cedar context. Its request fields are flattened on the wire.
type AuthRequest struct {
	ID      string               `json:"-"`
	Context map[string]AttrValue `json:"-"`
	Request Request              `json:"-"`
}

// AuthRequestOption configures an AuthRequest.
type AuthRequestOption func(*AuthRequest) error

// WithRequestID attaches an ID which the server returns with this batch item.
func WithRequestID(id string) AuthRequestOption {
	return func(request *AuthRequest) error {
		if err := validateRequestID(id); err != nil {
			return err
		}
		request.ID = id
		return nil
	}
}

// WithContext attaches request-scoped Cedar values. An empty context is
// omitted from the wire representation.
func WithContext(context map[string]AttrValue) AuthRequestOption {
	return func(request *AuthRequest) error {
		request.Context = make(map[string]AttrValue, len(context))
		for name, value := range context {
			if err := validateAttributeName("auth_request.context", name); err != nil {
				return err
			}
			if err := value.Validate(); err != nil {
				return fmt.Errorf("context attribute %q: %w", name, err)
			}
			request.Context[name] = value
		}
		return nil
	}
}

// NewAuthRequest constructs a validated batch item.
func NewAuthRequest(request Request, options ...AuthRequestOption) (AuthRequest, error) {
	authRequest := AuthRequest{Request: request}
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

// Validate checks the request, optional ID, context keys, and context values.
func (r AuthRequest) Validate() error {
	if r.ID != "" {
		if err := validateRequestID(r.ID); err != nil {
			return err
		}
	}
	for name, value := range r.Context {
		if err := validateAttributeName("auth_request.context", name); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return fmt.Errorf("context attribute %q: %w", name, err)
		}
	}
	return r.Request.Validate()
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
		ID: r.ID, Context: r.Context, Principal: r.Request.Principal,
		Action: r.Request.Action, Resource: r.Request.Resource,
	})
}

// UnmarshalJSON decodes and validates the flattened wire representation.
func (r *AuthRequest) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID        string               `json:"id"`
		Context   map[string]AttrValue `json:"context"`
		Principal Principal            `json:"principal"`
		Action    Action               `json:"action"`
		Resource  Resource             `json:"resource"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*r = AuthRequest{
		ID: wire.ID, Context: wire.Context,
		Request: Request{Principal: wire.Principal, Action: wire.Action, Resource: wire.Resource},
	}
	return r.Validate()
}

// AuthorizeRequest is a batch of authorization checks.
type AuthorizeRequest struct {
	Requests []AuthRequest `json:"requests"`
}

// MarshalJSON preserves an empty requests array for the Treetop wire contract.
func (r AuthorizeRequest) MarshalJSON() ([]byte, error) {
	requests := r.Requests
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
	r.Requests = *wire.Requests
	return r.Validate()
}

// NewAuthorizeRequest constructs and validates a batch. Empty batches are
// valid because compatible Treetop servers return an empty response.
func NewAuthorizeRequest(requests ...AuthRequest) (*AuthorizeRequest, error) {
	batch := &AuthorizeRequest{Requests: append([]AuthRequest(nil), requests...)}
	if batch.Requests == nil {
		batch.Requests = []AuthRequest{}
	}
	return batch, batch.Validate()
}

// SingleAuthorizeRequest constructs a one-item authorization batch.
func SingleAuthorizeRequest(request Request) *AuthorizeRequest {
	return &AuthorizeRequest{Requests: []AuthRequest{{Request: request}}}
}

// RequestsBatch constructs a batch from requests without item IDs or context.
func RequestsBatch(requests ...Request) (*AuthorizeRequest, error) {
	items := make([]AuthRequest, len(requests))
	for i, request := range requests {
		items[i] = AuthRequest{Request: request}
	}
	return NewAuthorizeRequest(items...)
}

// Validate checks every request and rejects duplicate item IDs.
func (r *AuthorizeRequest) Validate() error {
	if r == nil {
		return &ValidationError{Field: "authorize request", Rule: "must not be nil"}
	}
	ids := make(map[string]struct{}, len(r.Requests))
	for i, request := range r.Requests {
		if err := request.Validate(); err != nil {
			return fmt.Errorf("authorize request %d: %w", i, err)
		}
		if request.ID == "" {
			continue
		}
		if _, exists := ids[request.ID]; exists {
			return &ValidationError{Field: "request ID", Value: request.ID, Rule: "is duplicated in the batch"}
		}
		ids[request.ID] = struct{}{}
	}
	return nil
}

func (r *AuthorizeRequest) validateLimits(limits RequestLimits) error {
	if limits.MaxBatchSize > 0 && len(r.Requests) > limits.MaxBatchSize {
		return &ValidationError{Field: "authorization batch", Value: fmt.Sprint(len(r.Requests)), Rule: fmt.Sprintf("contains more than %d requests", limits.MaxBatchSize)}
	}
	for i, request := range r.Requests {
		if len(request.Context) == 0 {
			continue
		}
		if len(request.Context) > limits.MaxContextKeys {
			return &ValidationError{Field: fmt.Sprintf("requests[%d].context", i), Value: fmt.Sprint(len(request.Context)), Rule: fmt.Sprintf("contains more than %d keys", limits.MaxContextKeys)}
		}
		depth := 0
		for _, value := range request.Context {
			if current := attrDepth(value); current > depth {
				depth = current
			}
		}
		if depth > limits.MaxContextDepth {
			return &ValidationError{Field: fmt.Sprintf("requests[%d].context", i), Value: fmt.Sprint(depth), Rule: fmt.Sprintf("nesting exceeds depth %d", limits.MaxContextDepth)}
		}
		encoded, err := json.Marshal(request.Context)
		if err != nil {
			return fmt.Errorf("encode requests[%d].context: %w", i, err)
		}
		if int64(len(encoded)) > limits.MaxContextBytes {
			return &ValidationError{Field: fmt.Sprintf("requests[%d].context", i), Value: fmt.Sprintf("%d bytes", len(encoded)), Rule: fmt.Sprintf("exceeds %d bytes", limits.MaxContextBytes)}
		}
	}
	return nil
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
