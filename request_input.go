package treetop

// PrincipalInput is a raw user or group principal accepted by NewRequestFrom.
// The interface is intentionally sealed to the package's input types.
type PrincipalInput interface {
	requestPrincipalInput()
}

// GroupInput is raw group input. Namespace contains unqualified Cedar
// namespace segments and may be empty for the global namespace.
type GroupInput struct {
	// Name is the unqualified group entity ID.
	Name string
	// Namespace contains Cedar namespace segments in order.
	Namespace []string
}

func (GroupInput) requestPrincipalInput() {}

// UserInput is raw user input. GroupNames adds global groups; Groups supports
// namespace-qualified memberships.
type UserInput struct {
	// Name is the user entity ID.
	Name string
	// Namespace contains Cedar namespace segments in order.
	Namespace []string
	// GroupNames contains group IDs in the global namespace.
	GroupNames []string
	// Groups contains namespace-qualified memberships.
	Groups []GroupInput
}

func (UserInput) requestPrincipalInput() {}

// ResourceInput is raw resource input. Attributes may contain already typed
// Cedar values and is copied during validated construction.
type ResourceInput struct {
	// Type is a qualified Cedar entity type.
	Type string
	// ID is the resource entity ID.
	ID string
	// Attributes contains typed Cedar resource attributes.
	Attributes map[string]AttrValue
}

// RequestInput is the raw, non-domain representation accepted by
// NewRequestFrom. No invariants are promised until construction succeeds.
type RequestInput struct {
	// Principal is a UserInput or GroupInput.
	Principal PrincipalInput
	// Action is the action entity ID.
	Action string
	// ActionNamespace contains Cedar namespace segments in order.
	ActionNamespace []string
	// Resource identifies the authorization target.
	Resource ResourceInput
}

// NewRequestFrom converts raw input into an immutable validated Request.
func NewRequestFrom(input RequestInput) (Request, error) {
	builder := NewRequestBuilder()
	switch principal := input.Principal.(type) {
	case UserInput:
		applyUserInput(builder, principal)
	case *UserInput:
		if principal != nil {
			applyUserInput(builder, *principal)
		}
	case GroupInput:
		builder.Group(principal.Name, groupNamespaceInput(principal.Namespace))
	case *GroupInput:
		if principal != nil {
			builder.Group(principal.Name, groupNamespaceInput(principal.Namespace))
		}
	}

	builder.Action(input.Action, actionNamespaceInput(input.ActionNamespace))
	resourceOptions := make([]ResourceOption, 0, 1)
	if input.Resource.Attributes != nil {
		resourceOptions = append(resourceOptions, ResourceWithAttributes(input.Resource.Attributes))
	}
	builder.Resource(input.Resource.Type, input.Resource.ID, resourceOptions...)
	return builder.Build()
}

func applyUserInput(builder *RequestBuilder, input UserInput) {
	options := []UserOption{userNamespaceInput(input.Namespace)}
	if len(input.GroupNames) != 0 {
		options = append(options, UserInGroups(input.GroupNames...))
	}
	for _, group := range input.Groups {
		group := group
		options = append(options, func(user *User) error {
			validated, err := groupFromInput(group)
			if err != nil {
				return err
			}
			return UserWithGroups(validated)(user)
		})
	}
	builder.User(input.Name, options...)
}

func groupFromInput(input GroupInput) (Group, error) {
	namespace, err := NewNamespace(input.Namespace...)
	if err != nil {
		return Group{}, err
	}
	return NewGroup(input.Name, GroupWithNamespace(namespace))
}

func userNamespaceInput(segments []string) UserOption {
	copy := append([]string(nil), segments...)
	return func(user *User) error {
		namespace, err := NewNamespace(copy...)
		if err != nil {
			return err
		}
		return UserWithNamespace(namespace)(user)
	}
}

func groupNamespaceInput(segments []string) GroupOption {
	copy := append([]string(nil), segments...)
	return func(group *Group) error {
		namespace, err := NewNamespace(copy...)
		if err != nil {
			return err
		}
		return GroupWithNamespace(namespace)(group)
	}
}

func actionNamespaceInput(segments []string) ActionOption {
	copy := append([]string(nil), segments...)
	return func(action *Action) error {
		namespace, err := NewNamespace(copy...)
		if err != nil {
			return err
		}
		return ActionWithNamespace(namespace)(action)
	}
}
