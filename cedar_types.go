package treetop

import (
	"encoding/json"
	"strings"
)

// Namespace is an immutable, validated Cedar namespace. Its zero value is the
// global namespace.
//
// Use NewNamespace when constructing a namespace from segments and
// ParseNamespace when constructing one from a qualified Cedar path.
type Namespace struct {
	path string
}

// NewNamespace constructs a namespace from segments in outer-to-inner order.
// Calling NewNamespace without arguments returns the global namespace.
func NewNamespace(segments ...string) (Namespace, error) {
	if err := validateNamespace("namespace", segments); err != nil {
		return Namespace{}, err
	}
	return Namespace{path: strings.Join(segments, "::")}, nil
}

// ParseNamespace parses a qualified Cedar namespace such as "MyApp::Core".
// An empty string denotes the global namespace.
func ParseNamespace(value string) (Namespace, error) {
	if value == "" {
		return Namespace{}, nil
	}
	return NewNamespace(strings.Split(value, "::")...)
}

// String returns the namespace as a qualified Cedar path. It returns an empty
// string for the global namespace.
func (n Namespace) String() string { return n.path }

// Segments returns a new slice containing the namespace segments in
// outer-to-inner order.
func (n Namespace) Segments() []string {
	if n.path == "" {
		return []string{}
	}
	return strings.Split(n.path, "::")
}

// IsEmpty reports whether n is the global namespace.
func (n Namespace) IsEmpty() bool { return n.path == "" }

// Validate checks the namespace's Cedar identifier invariants.
func (n Namespace) Validate() error {
	return n.validate("namespace")
}

func (n Namespace) validate(field string) error {
	if n.path == "" {
		return nil
	}
	return validateCedarPath(field, n.path)
}

// MarshalJSON implements Treetop's namespace-segment array representation.
func (n Namespace) MarshalJSON() ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(n.Segments())
}

// UnmarshalJSON decodes and validates a Treetop namespace-segment array.
func (n *Namespace) UnmarshalJSON(data []byte) error {
	if n == nil {
		return &ValidationError{Field: "namespace", Rule: "destination must not be nil"}
	}
	var segments *[]string
	if err := json.Unmarshal(data, &segments); err != nil {
		return err
	}
	if segments == nil {
		return &ValidationError{Field: "namespace", Rule: "must be an array of Cedar identifiers"}
	}
	parsed, err := NewNamespace((*segments)...)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// EntityType is an immutable, validated, qualified Cedar entity type such as
// "Document" or "MyApp::Document". Its zero value is invalid.
type EntityType struct {
	name string
}

// NewEntityType constructs a validated Cedar entity type.
func NewEntityType(value string) (EntityType, error) {
	if err := validateCedarPath("entity type", value); err != nil {
		return EntityType{}, err
	}
	return EntityType{name: value}, nil
}

// String returns the qualified Cedar entity type.
func (t EntityType) String() string { return t.name }

// Validate checks the entity type's Cedar identifier invariants.
func (t EntityType) Validate() error {
	return t.validate("entity type")
}

func (t EntityType) validate(field string) error { return validateCedarPath(field, t.name) }

// MarshalJSON encodes the entity type as its qualified Cedar string.
func (t EntityType) MarshalJSON() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(t.name)
}

// UnmarshalJSON decodes and validates a qualified Cedar entity type.
func (t *EntityType) UnmarshalJSON(data []byte) error {
	if t == nil {
		return &ValidationError{Field: "entity type", Rule: "destination must not be nil"}
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parsed, err := NewEntityType(value)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

type entityID struct {
	value string
	set   bool
}

func newEntityID(field, value string) (entityID, error) {
	if err := validateEntityID(field, value); err != nil {
		return entityID{}, err
	}
	return entityID{value: value, set: true}, nil
}

func (id entityID) validate(field string) error {
	if !id.set {
		return &ValidationError{Field: field, Rule: "must be constructed by the package"}
	}
	return validateEntityID(field, id.value)
}

func (id entityID) String() string { return id.value }

type requestID struct {
	value string
	set   bool
}

func newRequestID(value string) (requestID, error) {
	if err := validateRequestID(value); err != nil {
		return requestID{}, err
	}
	return requestID{value: value, set: true}, nil
}

func (id requestID) validate() error {
	if !id.set {
		return &ValidationError{Field: "request ID", Rule: "must be constructed by the package"}
	}
	return validateRequestID(id.value)
}

func (id requestID) String() string { return id.value }
