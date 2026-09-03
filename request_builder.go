package treetop

import (
	"fmt"
	"strings"
)

// RequestBuildError reports one or more independent failures encountered
// while converting request-boundary input into a validated Request.
type RequestBuildError struct {
	errors []error
}

// Error summarizes every failed request field.
func (e *RequestBuildError) Error() string {
	if e == nil || len(e.errors) == 0 {
		return "treetop: authorization request build failed"
	}
	messages := make([]string, len(e.errors))
	for i, err := range e.errors {
		messages[i] = err.Error()
	}
	return "treetop: authorization request build failed: " + strings.Join(messages, "; ")
}

// Errors returns a copy of the individual field errors.
func (e *RequestBuildError) Errors() []error {
	if e == nil {
		return nil
	}
	return append([]error(nil), e.errors...)
}

// Unwrap exposes every field error to errors.Is and errors.As.
func (e *RequestBuildError) Unwrap() []error {
	return e.Errors()
}

type requestBuilderPrincipal uint8

const (
	requestBuilderNoPrincipal requestBuilderPrincipal = iota
	requestBuilderUser
	requestBuilderGroup
)

// RequestBuilder collects raw request-boundary values and converts them into
// one validated authorization request at Build time. It is intended for
// request-scoped use and is not safe for concurrent mutation.
type RequestBuilder struct {
	principalKind requestBuilderPrincipal
	principalID   string
	userOptions   []UserOption
	groupOptions  []GroupOption
	actionID      string
	actionOptions []ActionOption
	resourceType  string
	resourceID    string
	resourceOpts  []ResourceOption
	actionSet     bool
	resourceSet   bool
	inputErrors   []error
}

// NewRequestBuilder starts an empty authorization request builder.
func NewRequestBuilder() *RequestBuilder {
	return &RequestBuilder{}
}

// User sets raw input for a user principal. Call it exactly once, instead of
// Group. Validation is deferred until Build.
func (b *RequestBuilder) User(id string, options ...UserOption) *RequestBuilder {
	if b == nil {
		return nil
	}
	if b.principalKind != requestBuilderNoPrincipal {
		b.duplicate("principal")
		return b
	}
	b.principalKind = requestBuilderUser
	b.principalID = id
	b.userOptions = append([]UserOption(nil), options...)
	return b
}

// Group sets raw input for a group principal. Call it exactly once, instead
// of User. Validation is deferred until Build.
func (b *RequestBuilder) Group(id string, options ...GroupOption) *RequestBuilder {
	if b == nil {
		return nil
	}
	if b.principalKind != requestBuilderNoPrincipal {
		b.duplicate("principal")
		return b
	}
	b.principalKind = requestBuilderGroup
	b.principalID = id
	b.groupOptions = append([]GroupOption(nil), options...)
	return b
}

// Action sets raw action input. Call it exactly once. Validation is deferred
// until Build.
func (b *RequestBuilder) Action(id string, options ...ActionOption) *RequestBuilder {
	if b == nil {
		return nil
	}
	if b.actionSet {
		b.duplicate("action")
		return b
	}
	b.actionSet = true
	b.actionID = id
	b.actionOptions = append([]ActionOption(nil), options...)
	return b
}

// Resource sets raw resource input. Call it exactly once. Validation is
// deferred until Build.
func (b *RequestBuilder) Resource(kind, id string, options ...ResourceOption) *RequestBuilder {
	if b == nil {
		return nil
	}
	if b.resourceSet {
		b.duplicate("resource")
		return b
	}
	b.resourceSet = true
	b.resourceType = kind
	b.resourceID = id
	b.resourceOpts = append([]ResourceOption(nil), options...)
	return b
}

// Build converts all raw fields through the ordinary validated constructors.
// Independent principal, action, and resource failures are returned together.
func (b *RequestBuilder) Build() (Request, error) {
	if b == nil {
		return Request{}, &ConfigurationError{Message: "request builder must not be nil"}
	}
	errors := append([]error(nil), b.inputErrors...)

	var principal Principal
	switch b.principalKind {
	case requestBuilderUser:
		user, err := NewUser(b.principalID, b.userOptions...)
		if err != nil {
			errors = append(errors, fmt.Errorf("principal: %w", err))
		} else {
			principal = UserPrincipal(user)
		}
	case requestBuilderGroup:
		group, err := NewGroup(b.principalID, b.groupOptions...)
		if err != nil {
			errors = append(errors, fmt.Errorf("principal: %w", err))
		} else {
			principal = GroupPrincipal(group)
		}
	default:
		errors = append(errors, &ValidationError{Field: "principal", Rule: "must be set with User or Group"})
	}

	var action Action
	if !b.actionSet {
		errors = append(errors, &ValidationError{Field: "action", Rule: "must be set"})
	} else {
		var err error
		action, err = NewAction(b.actionID, b.actionOptions...)
		if err != nil {
			errors = append(errors, fmt.Errorf("action: %w", err))
		}
	}

	var resource Resource
	if !b.resourceSet {
		errors = append(errors, &ValidationError{Field: "resource", Rule: "must be set"})
	} else {
		var err error
		resource, err = NewResource(b.resourceType, b.resourceID, b.resourceOpts...)
		if err != nil {
			errors = append(errors, fmt.Errorf("resource: %w", err))
		}
	}

	if len(errors) != 0 {
		return Request{}, &RequestBuildError{errors: errors}
	}
	request, err := NewRequest(principal, action, resource)
	if err != nil {
		return Request{}, &RequestBuildError{errors: []error{fmt.Errorf("request: %w", err)}}
	}
	return request, nil
}

func (b *RequestBuilder) duplicate(field string) {
	b.inputErrors = append(b.inputErrors, &ConfigurationError{Message: "request builder " + field + " was set more than once"})
}
