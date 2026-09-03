package treetop

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Group is a Cedar group entity with an optional namespace.
type Group struct {
	ID        string   `json:"id"`
	Namespace []string `json:"namespace"`
}

// NewGroup constructs and validates a group. Namespace arguments are Cedar
// namespace segments in outer-to-inner order.
func NewGroup(id string, namespace ...string) (Group, error) {
	g := Group{ID: id, Namespace: cloneStrings(namespace)}
	return g, g.Validate()
}

// Validate checks the group's Cedar and Treetop wire invariants.
func (g Group) Validate() error {
	if err := validateEntityID("group.id", g.ID); err != nil {
		return err
	}
	return validateNamespace("group.namespace", g.Namespace)
}

// MarshalJSON preserves an empty namespace array for the Treetop wire contract.
func (g Group) MarshalJSON() ([]byte, error) {
	type wire Group
	copy := wire(g)
	if copy.Namespace == nil {
		copy.Namespace = []string{}
	}
	return json.Marshal(copy)
}

// UnmarshalJSON decodes and validates a group.
func (g *Group) UnmarshalJSON(data []byte) error {
	type wire Group
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*g = Group(decoded)
	if g.Namespace == nil {
		g.Namespace = []string{}
	}
	return g.Validate()
}

// User is a Cedar user entity with optional namespace and group membership.
type User struct {
	ID        string   `json:"id"`
	Namespace []string `json:"namespace"`
	Groups    []Group  `json:"groups"`
}

// UserOption configures a User during validated construction.
type UserOption func(*User) error

// UserWithNamespace sets Cedar namespace segments in outer-to-inner order.
func UserWithNamespace(namespace ...string) UserOption {
	return func(user *User) error {
		user.Namespace = cloneStrings(namespace)
		return validateNamespace("user.namespace", user.Namespace)
	}
}

// UserWithGroups sets the user's group memberships.
func UserWithGroups(groups ...Group) UserOption {
	return func(user *User) error {
		user.Groups = append([]Group(nil), groups...)
		for _, group := range user.Groups {
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
		user.Groups = groups
		return nil
	}
}

// NewUser constructs and validates a user.
func NewUser(id string, options ...UserOption) (User, error) {
	user := User{ID: id, Namespace: []string{}, Groups: []Group{}}
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

// Validate checks the user and all group memberships.
func (u User) Validate() error {
	if err := validateEntityID("user.id", u.ID); err != nil {
		return err
	}
	if err := validateNamespace("user.namespace", u.Namespace); err != nil {
		return err
	}
	for _, group := range u.Groups {
		if err := group.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// MarshalJSON preserves the Treetop contract's empty arrays for namespace and
// groups, including for a zero-length nil slice.
func (u User) MarshalJSON() ([]byte, error) {
	type wire User
	copy := wire(u)
	if copy.Namespace == nil {
		copy.Namespace = []string{}
	}
	if copy.Groups == nil {
		copy.Groups = []Group{}
	}
	return json.Marshal(copy)
}

// UnmarshalJSON decodes and validates a user and its groups.
func (u *User) UnmarshalJSON(data []byte) error {
	type wire User
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*u = User(decoded)
	if u.Namespace == nil {
		u.Namespace = []string{}
	}
	if u.Groups == nil {
		u.Groups = []Group{}
	}
	return u.Validate()
}

// Principal is exactly one user or group. Use UserPrincipal or GroupPrincipal
// to construct it.
type Principal struct {
	User  *User  `json:"-"`
	Group *Group `json:"-"`
}

// UserPrincipal makes user the principal of an authorization request.
func UserPrincipal(user User) Principal {
	copy := user
	return Principal{User: &copy}
}

// GroupPrincipal makes group the principal of an authorization request.
func GroupPrincipal(group Group) Principal {
	copy := group
	return Principal{Group: &copy}
}

// Validate ensures exactly one valid principal variant is set.
func (p Principal) Validate() error {
	switch {
	case p.User != nil && p.Group == nil:
		return p.User.Validate()
	case p.Group != nil && p.User == nil:
		return p.Group.Validate()
	default:
		return &ValidationError{Field: "principal", Rule: "must contain exactly one of User or Group"}
	}
}

// MarshalJSON implements Treetop's externally tagged principal representation.
func (p Principal) MarshalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.User != nil {
		return json.Marshal(struct {
			User User `json:"User"`
		}{User: *p.User})
	}
	return json.Marshal(struct {
		Group Group `json:"Group"`
	}{Group: *p.Group})
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
	ID        string   `json:"id"`
	Namespace []string `json:"namespace"`
}

// NewAction constructs and validates an action. Namespace arguments are Cedar
// namespace segments in outer-to-inner order.
func NewAction(id string, namespace ...string) (Action, error) {
	action := Action{ID: id, Namespace: cloneStrings(namespace)}
	return action, action.Validate()
}

// Validate checks the action's Treetop wire invariants.
func (a Action) Validate() error {
	if err := validateEntityID("action.id", a.ID); err != nil {
		return err
	}
	return validateNamespace("action.namespace", a.Namespace)
}

// MarshalJSON preserves an empty namespace array for the Treetop wire contract.
func (a Action) MarshalJSON() ([]byte, error) {
	type wire Action
	copy := wire(a)
	if copy.Namespace == nil {
		copy.Namespace = []string{}
	}
	return json.Marshal(copy)
}

// UnmarshalJSON decodes and validates an action.
func (a *Action) UnmarshalJSON(data []byte) error {
	type wire Action
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*a = Action(decoded)
	if a.Namespace == nil {
		a.Namespace = []string{}
	}
	return a.Validate()
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
	Kind  string               `json:"kind"`
	ID    string               `json:"id"`
	Attrs map[string]AttrValue `json:"attrs,omitempty"`
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
		resource.Attrs[name] = value
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
func NewResource(kind, id string, options ...ResourceOption) (Resource, error) {
	resource := Resource{Kind: kind, ID: id, Attrs: make(map[string]AttrValue)}
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

// Validate checks the resource type, ID, keys, and values.
func (r Resource) Validate() error {
	if err := validateCedarPath("resource.kind", r.Kind); err != nil {
		return err
	}
	if err := validateEntityID("resource.id", r.ID); err != nil {
		return err
	}
	for name, value := range r.Attrs {
		if err := validateAttributeName("resource.attrs", name); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return fmt.Errorf("resource attribute %q: %w", name, err)
		}
	}
	return nil
}

// UnmarshalJSON decodes and validates a resource.
func (r *Resource) UnmarshalJSON(data []byte) error {
	type wire Resource
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = Resource(decoded)
	return r.Validate()
}

// Request is one principal/action/resource authorization check.
type Request struct {
	Principal Principal `json:"principal"`
	Action    Action    `json:"action"`
	Resource  Resource  `json:"resource"`
}

// NewRequest constructs a request. It remains validated again immediately
// before transport to catch later mutation of exported fields.
func NewRequest(principal Principal, action Action, resource Resource) (Request, error) {
	request := Request{Principal: principal, Action: action, Resource: resource}
	return request, request.Validate()
}

// Validate checks every request-domain value.
func (r Request) Validate() error {
	if err := r.Principal.Validate(); err != nil {
		return err
	}
	if err := r.Action.Validate(); err != nil {
		return err
	}
	return r.Resource.Validate()
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}
