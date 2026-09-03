package treetop

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Group is a Cedar group entity with an optional namespace.
type Group struct {
	id        entityID
	namespace Namespace
}

// GroupOption configures a Group during validated construction.
type GroupOption func(*Group) error

// GroupWithNamespace sets a validated Cedar namespace.
func GroupWithNamespace(namespace Namespace) GroupOption {
	return func(group *Group) error {
		if err := namespace.validate("group.namespace"); err != nil {
			return err
		}
		group.namespace = namespace
		return nil
	}
}

// NewGroup constructs and validates a group.
func NewGroup(id string, options ...GroupOption) (Group, error) {
	validatedID, err := newEntityID("group.id", id)
	if err != nil {
		return Group{}, err
	}
	group := Group{id: validatedID}
	for _, option := range options {
		if option == nil {
			return Group{}, &ConfigurationError{Message: "nil group option"}
		}
		if err := option(&group); err != nil {
			return Group{}, err
		}
	}
	return group, group.Validate()
}

// ID returns the group entity identifier.
func (g Group) ID() string { return g.id.String() }

// Namespace returns the group's immutable Cedar namespace.
func (g Group) Namespace() Namespace { return g.namespace }

// Validate checks the group's Cedar and Treetop wire invariants.
func (g Group) Validate() error {
	if err := g.id.validate("group.id"); err != nil {
		return err
	}
	return g.namespace.validate("group.namespace")
}

// MarshalJSON preserves an empty namespace array for the Treetop wire contract.
func (g Group) MarshalJSON() ([]byte, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ID        string    `json:"id"`
		Namespace Namespace `json:"namespace"`
	}{ID: g.ID(), Namespace: g.namespace})
}

// UnmarshalJSON decodes and validates a group.
func (g *Group) UnmarshalJSON(data []byte) error {
	var decoded struct {
		ID        *string   `json:"id"`
		Namespace Namespace `json:"namespace"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.ID == nil {
		return &ValidationError{Field: "group.id", Rule: "is required"}
	}
	parsed, err := NewGroup(*decoded.ID, GroupWithNamespace(decoded.Namespace))
	if err != nil {
		return err
	}
	*g = parsed
	return nil
}

// User is a Cedar user entity with optional namespace and group membership.
type User struct {
	id        entityID
	namespace Namespace
	groups    []Group
}

// UserOption configures a User during validated construction.
type UserOption func(*User) error

// UserWithNamespace sets a validated Cedar namespace.
func UserWithNamespace(namespace Namespace) UserOption {
	return func(user *User) error {
		if err := namespace.validate("user.namespace"); err != nil {
			return err
		}
		user.namespace = namespace
		return nil
	}
}

// UserWithGroups sets the user's group memberships.
func UserWithGroups(groups ...Group) UserOption {
	return func(user *User) error {
		user.groups = append([]Group(nil), groups...)
		for _, group := range user.groups {
			if err := group.Validate(); err != nil {
				return err
			}
		}
		return nil
	}
}

// UserWithGroupNames adds non-namespaced group memberships.
func UserWithGroupNames(names ...string) UserOption {
	return func(user *User) error {
		groups := make([]Group, 0, len(names))
		for _, name := range names {
			group, err := NewGroup(name)
			if err != nil {
				return err
			}
			groups = append(groups, group)
		}
		user.groups = groups
		return nil
	}
}

// NewUser constructs and validates a user.
func NewUser(id string, options ...UserOption) (User, error) {
	validatedID, err := newEntityID("user.id", id)
	if err != nil {
		return User{}, err
	}
	user := User{id: validatedID, groups: []Group{}}
	for _, option := range options {
		if option == nil {
			return User{}, &ConfigurationError{Message: "nil user option"}
		}
		if err := option(&user); err != nil {
			return User{}, err
		}
	}
	return user, user.Validate()
}

// ID returns the user entity identifier.
func (u User) ID() string { return u.id.String() }

// Namespace returns the user's immutable Cedar namespace.
func (u User) Namespace() Namespace { return u.namespace }

// Groups returns a copy of the user's group memberships.
func (u User) Groups() []Group { return append([]Group(nil), u.groups...) }

// Validate checks the user and all group memberships.
func (u User) Validate() error {
	if err := u.id.validate("user.id"); err != nil {
		return err
	}
	if err := u.namespace.validate("user.namespace"); err != nil {
		return err
	}
	for _, group := range u.groups {
		if err := group.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// MarshalJSON preserves the Treetop contract's empty arrays for namespace and
// groups, including for a zero-length nil slice.
func (u User) MarshalJSON() ([]byte, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	groups := u.groups
	if groups == nil {
		groups = []Group{}
	}
	return json.Marshal(struct {
		ID        string    `json:"id"`
		Namespace Namespace `json:"namespace"`
		Groups    []Group   `json:"groups"`
	}{ID: u.ID(), Namespace: u.namespace, Groups: groups})
}

// UnmarshalJSON decodes and validates a user and its groups.
func (u *User) UnmarshalJSON(data []byte) error {
	var decoded struct {
		ID        *string   `json:"id"`
		Namespace Namespace `json:"namespace"`
		Groups    []Group   `json:"groups"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.ID == nil {
		return &ValidationError{Field: "user.id", Rule: "is required"}
	}
	parsed, err := NewUser(*decoded.ID, UserWithNamespace(decoded.Namespace), UserWithGroups(decoded.Groups...))
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}

// Principal is exactly one user or group. Use UserPrincipal or GroupPrincipal
// to construct it.
type Principal struct {
	kind  principalKind
	user  User
	group Group
}

type principalKind uint8

const (
	principalUser principalKind = iota + 1
	principalGroup
)

// UserPrincipal makes user the principal of an authorization request.
func UserPrincipal(user User) Principal {
	return Principal{kind: principalUser, user: user}
}

// GroupPrincipal makes group the principal of an authorization request.
func GroupPrincipal(group Group) Principal {
	return Principal{kind: principalGroup, group: group}
}

// User returns the user when this is a user principal.
func (p Principal) User() (User, bool) { return p.user, p.kind == principalUser }

// Group returns the group when this is a group principal.
func (p Principal) Group() (Group, bool) { return p.group, p.kind == principalGroup }

// Validate ensures exactly one valid principal variant is set.
func (p Principal) Validate() error {
	switch p.kind {
	case principalUser:
		return p.user.Validate()
	case principalGroup:
		return p.group.Validate()
	default:
		return &ValidationError{Field: "principal", Rule: "must contain exactly one of User or Group"}
	}
}

// MarshalJSON implements Treetop's externally tagged principal representation.
func (p Principal) MarshalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.kind == principalUser {
		return json.Marshal(struct {
			User User `json:"User"`
		}{User: p.user})
	}
	return json.Marshal(struct {
		Group Group `json:"Group"`
	}{Group: p.group})
}

// UnmarshalJSON decodes and validates an externally tagged principal.
func (p *Principal) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) != 1 {
		return &ValidationError{Field: "principal", Rule: "must contain exactly one of User or Group"}
	}
	if value, ok := raw["User"]; ok {
		var user User
		if err := json.Unmarshal(value, &user); err != nil {
			return err
		}
		if err := user.Validate(); err != nil {
			return err
		}
		*p = UserPrincipal(user)
		return nil
	}
	if value, ok := raw["Group"]; ok {
		var group Group
		if err := json.Unmarshal(value, &group); err != nil {
			return err
		}
		if err := group.Validate(); err != nil {
			return err
		}
		*p = GroupPrincipal(group)
		return nil
	}
	return &ValidationError{Field: "principal", Rule: "unknown principal variant"}
}

// Action identifies the operation in a Cedar authorization request.
type Action struct {
	id        entityID
	namespace Namespace
}

// ActionOption configures an Action during validated construction.
type ActionOption func(*Action) error

// ActionWithNamespace sets a validated Cedar namespace.
func ActionWithNamespace(namespace Namespace) ActionOption {
	return func(action *Action) error {
		if err := namespace.validate("action.namespace"); err != nil {
			return err
		}
		action.namespace = namespace
		return nil
	}
}

// NewAction constructs and validates an action.
func NewAction(id string, options ...ActionOption) (Action, error) {
	validatedID, err := newEntityID("action.id", id)
	if err != nil {
		return Action{}, err
	}
	action := Action{id: validatedID}
	for _, option := range options {
		if option == nil {
			return Action{}, &ConfigurationError{Message: "nil action option"}
		}
		if err := option(&action); err != nil {
			return Action{}, err
		}
	}
	return action, action.Validate()
}

// ID returns the action entity identifier.
func (a Action) ID() string { return a.id.String() }

// Namespace returns the action's immutable Cedar namespace.
func (a Action) Namespace() Namespace { return a.namespace }

// Validate checks the action's Treetop wire invariants.
func (a Action) Validate() error {
	if err := a.id.validate("action.id"); err != nil {
		return err
	}
	return a.namespace.validate("action.namespace")
}

// MarshalJSON preserves an empty namespace array for the Treetop wire contract.
func (a Action) MarshalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ID        string    `json:"id"`
		Namespace Namespace `json:"namespace"`
	}{ID: a.ID(), Namespace: a.namespace})
}

// UnmarshalJSON decodes and validates an action.
func (a *Action) UnmarshalJSON(data []byte) error {
	var decoded struct {
		ID        *string   `json:"id"`
		Namespace Namespace `json:"namespace"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.ID == nil {
		return &ValidationError{Field: "action.id", Rule: "is required"}
	}
	parsed, err := NewAction(*decoded.ID, ActionWithNamespace(decoded.Namespace))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// AttrType is the Treetop wire tag for a Cedar attribute value.
type AttrType string

const (
	AttrTypeString AttrType = "String"
	AttrTypeBool   AttrType = "Bool"
	AttrTypeLong   AttrType = "Long"
	AttrTypeIP     AttrType = "Ip"
	AttrTypeSet    AttrType = "Set"
)

// AttrValue is a typed Cedar resource or context attribute. Construct values
// with StringValue, BoolValue, LongValue, IPValue, or SetValue.
type AttrValue struct {
	typeName AttrType
	value    any
}

// StringValue constructs a Cedar string attribute.
func StringValue(value string) AttrValue { return AttrValue{typeName: AttrTypeString, value: value} }

// BoolValue constructs a Cedar Boolean attribute.
func BoolValue(value bool) AttrValue { return AttrValue{typeName: AttrTypeBool, value: value} }

// LongValue constructs a Cedar signed 64-bit integer attribute.
func LongValue(value int64) AttrValue { return AttrValue{typeName: AttrTypeLong, value: value} }

// IPValue constructs and validates a Cedar IP address or CIDR extension value.
func IPValue(value string) (AttrValue, error) {
	if err := validateIP(value); err != nil {
		return AttrValue{}, err
	}
	return AttrValue{typeName: AttrTypeIP, value: value}, nil
}

// SetValue constructs a Cedar set attribute.
func SetValue(values ...AttrValue) AttrValue {
	return AttrValue{typeName: AttrTypeSet, value: append([]AttrValue(nil), values...)}
}

// Type returns the value's Treetop wire tag.
func (v AttrValue) Type() AttrType { return v.typeName }

// Value returns the underlying string, bool, int64, or a copy of the
// []AttrValue set. Callers should normally switch on Type first.
func (v AttrValue) Value() any {
	if values, ok := v.value.([]AttrValue); ok {
		return append([]AttrValue(nil), values...)
	}
	return v.value
}

// Validate checks the type and value recursively.
func (v AttrValue) Validate() error {
	pending := []AttrValue{v}
	for len(pending) > 0 {
		last := len(pending) - 1
		current := pending[last]
		pending = pending[:last]
		switch current.typeName {
		case AttrTypeString:
			if _, ok := current.value.(string); !ok {
				return invalidAttrType(current.typeName)
			}
		case AttrTypeBool:
			if _, ok := current.value.(bool); !ok {
				return invalidAttrType(current.typeName)
			}
		case AttrTypeLong:
			if _, ok := current.value.(int64); !ok {
				return invalidAttrType(current.typeName)
			}
		case AttrTypeIP:
			value, ok := current.value.(string)
			if !ok {
				return invalidAttrType(current.typeName)
			}
			if err := validateIP(value); err != nil {
				return err
			}
		case AttrTypeSet:
			values, ok := current.value.([]AttrValue)
			if !ok {
				return invalidAttrType(current.typeName)
			}
			pending = append(pending, values...)
		default:
			return &ValidationError{Field: "attribute type", Value: string(current.typeName), Rule: "is not supported"}
		}
	}
	return nil
}

func invalidAttrType(kind AttrType) error {
	return &ValidationError{Field: "attribute value", Value: string(kind), Rule: "does not match its type tag"}
}

// MarshalJSON implements the {"type": ..., "value": ...} wire format.
func (v AttrValue) MarshalJSON() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Type  AttrType `json:"type"`
		Value any      `json:"value"`
	}{Type: v.typeName, Value: v.value})
}

// UnmarshalJSON decodes and validates a typed Cedar attribute.
func (v *AttrValue) UnmarshalJSON(data []byte) error {
	var header struct {
		Type  AttrType        `json:"type"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return err
	}
	var value any
	switch header.Type {
	case AttrTypeString, AttrTypeIP:
		var decoded string
		if err := json.Unmarshal(header.Value, &decoded); err != nil {
			return err
		}
		value = decoded
	case AttrTypeBool:
		var decoded bool
		if err := json.Unmarshal(header.Value, &decoded); err != nil {
			return err
		}
		value = decoded
	case AttrTypeLong:
		var decoded int64
		decoder := json.NewDecoder(bytes.NewReader(header.Value))
		if err := decoder.Decode(&decoded); err != nil {
			return err
		}
		value = decoded
	case AttrTypeSet:
		var decoded []AttrValue
		if err := json.Unmarshal(header.Value, &decoded); err != nil {
			return err
		}
		value = decoded
	default:
		return &ValidationError{Field: "attribute type", Value: string(header.Type), Rule: "is not supported"}
	}
	*v = AttrValue{typeName: header.Type, value: value}
	return v.Validate()
}

// Resource is the target entity in an authorization request.
type Resource struct {
	kind  EntityType
	id    entityID
	attrs map[string]AttrValue
}

// ResourceOption configures a Resource during validated construction.
type ResourceOption func(*Resource) error

// ResourceWithAttribute adds or replaces one resource attribute.
func ResourceWithAttribute(name string, value AttrValue) ResourceOption {
	return func(resource *Resource) error {
		if err := validateAttributeName("resource.attrs", name); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		resource.attrs[name] = value
		return nil
	}
}

// ResourceWithAttributes adds a copy of the supplied attributes.
func ResourceWithAttributes(attrs map[string]AttrValue) ResourceOption {
	return func(resource *Resource) error {
		for name, value := range attrs {
			if err := ResourceWithAttribute(name, value)(resource); err != nil {
				return err
			}
		}
		return nil
	}
}

// NewResource constructs and validates a resource.
func NewResource(kind EntityType, id string, options ...ResourceOption) (Resource, error) {
	if err := kind.validate("resource.kind"); err != nil {
		return Resource{}, err
	}
	validatedID, err := newEntityID("resource.id", id)
	if err != nil {
		return Resource{}, err
	}
	resource := Resource{kind: kind, id: validatedID, attrs: make(map[string]AttrValue)}
	for _, option := range options {
		if option == nil {
			return Resource{}, &ConfigurationError{Message: "nil resource option"}
		}
		if err := option(&resource); err != nil {
			return Resource{}, err
		}
	}
	return resource, resource.Validate()
}

// Kind returns the resource's immutable Cedar entity type.
func (r Resource) Kind() EntityType { return r.kind }

// ID returns the resource entity identifier.
func (r Resource) ID() string { return r.id.String() }

// Attributes returns a copy of the resource attributes.
func (r Resource) Attributes() map[string]AttrValue {
	attrs := make(map[string]AttrValue, len(r.attrs))
	for name, value := range r.attrs {
		attrs[name] = value
	}
	return attrs
}

// Attribute returns a resource attribute by name.
func (r Resource) Attribute(name string) (AttrValue, bool) {
	value, ok := r.attrs[name]
	return value, ok
}

// Validate checks the resource type, ID, keys, and values.
func (r Resource) Validate() error {
	if err := r.kind.validate("resource.kind"); err != nil {
		return err
	}
	if err := r.id.validate("resource.id"); err != nil {
		return err
	}
	for name, value := range r.attrs {
		if err := validateAttributeName("resource.attrs", name); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return fmt.Errorf("resource attribute %q: %w", name, err)
		}
	}
	return nil
}

// MarshalJSON implements the validated Treetop resource representation.
func (r Resource) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Kind  EntityType           `json:"kind"`
		ID    string               `json:"id"`
		Attrs map[string]AttrValue `json:"attrs,omitempty"`
	}{Kind: r.kind, ID: r.ID(), Attrs: r.attrs})
}

// UnmarshalJSON decodes and validates a resource.
func (r *Resource) UnmarshalJSON(data []byte) error {
	var decoded struct {
		Kind  *EntityType          `json:"kind"`
		ID    *string              `json:"id"`
		Attrs map[string]AttrValue `json:"attrs"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.Kind == nil {
		return &ValidationError{Field: "resource.kind", Rule: "is required"}
	}
	if decoded.ID == nil {
		return &ValidationError{Field: "resource.id", Rule: "is required"}
	}
	parsed, err := NewResource(*decoded.Kind, *decoded.ID, ResourceWithAttributes(decoded.Attrs))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// Request is one principal/action/resource authorization check.
type Request struct {
	principal Principal
	action    Action
	resource  Resource
}

// NewRequest constructs and validates an immutable authorization request.
func NewRequest(principal Principal, action Action, resource Resource) (Request, error) {
	request := Request{principal: principal, action: action, resource: resource}
	return request, request.Validate()
}

// Principal returns the request principal.
func (r Request) Principal() Principal { return r.principal }

// Action returns the requested action.
func (r Request) Action() Action { return r.action }

// Resource returns the target resource.
func (r Request) Resource() Resource { return r.resource }

// Validate checks every request-domain value.
func (r Request) Validate() error {
	if err := r.principal.Validate(); err != nil {
		return err
	}
	if err := r.action.Validate(); err != nil {
		return err
	}
	return r.resource.Validate()
}

// MarshalJSON implements the validated Treetop request representation.
func (r Request) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Principal Principal `json:"principal"`
		Action    Action    `json:"action"`
		Resource  Resource  `json:"resource"`
	}{Principal: r.principal, Action: r.action, Resource: r.resource})
}

// UnmarshalJSON decodes and validates a Treetop request.
func (r *Request) UnmarshalJSON(data []byte) error {
	var decoded struct {
		Principal Principal `json:"principal"`
		Action    Action    `json:"action"`
		Resource  Resource  `json:"resource"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	parsed, err := NewRequest(decoded.Principal, decoded.Action, decoded.Resource)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}
