package treetop

// Network calls validate the complete request once and then convert it to these
// plain wire values so nested MarshalJSON methods do not repeatedly walk the
// same attribute trees.

type groupWire struct {
	ID        string   `json:"id"`
	Namespace []string `json:"namespace"`
}

type userWire struct {
	ID        string      `json:"id"`
	Namespace []string    `json:"namespace"`
	Groups    []groupWire `json:"groups"`
}

type principalWire struct {
	User  *userWire  `json:"User,omitempty"`
	Group *groupWire `json:"Group,omitempty"`
}

type actionWire struct {
	ID        string   `json:"id"`
	Namespace []string `json:"namespace"`
}

type attrValueWire struct {
	Type  AttrType `json:"type"`
	Value any      `json:"value"`
}

type resourceWire struct {
	Kind  string                   `json:"kind"`
	ID    string                   `json:"id"`
	Attrs map[string]attrValueWire `json:"attrs,omitempty"`
}

type authRequestWire struct {
	ID        string                   `json:"id,omitempty"`
	Context   map[string]attrValueWire `json:"context,omitempty"`
	Principal principalWire            `json:"principal"`
	Action    actionWire               `json:"action"`
	Resource  resourceWire             `json:"resource"`
}

type authorizeRequestWire struct {
	Requests []authRequestWire `json:"requests"`
}

func toAuthorizeRequestWire(request *AuthorizeRequest) authorizeRequestWire {
	requests := make([]authRequestWire, len(request.requests))
	for i, item := range request.requests {
		requests[i] = toAuthRequestWire(item)
	}
	return authorizeRequestWire{Requests: requests}
}

func toAuthRequestWire(request AuthRequest) authRequestWire {
	return authRequestWire{
		ID: request.id.String(), Context: toAttrMapWire(request.context),
		Principal: toPrincipalWire(request.request.principal),
		Action:    toActionWire(request.request.action),
		Resource:  toResourceWire(request.request.resource),
	}
}

func toPrincipalWire(principal Principal) principalWire {
	switch principal.kind {
	case principalUser:
		user := toUserWire(principal.user)
		return principalWire{User: &user}
	case principalGroup:
		group := toGroupWire(principal.group)
		return principalWire{Group: &group}
	default:
		return principalWire{}
	}
}

func toUserWire(user User) userWire {
	groups := make([]groupWire, len(user.groups))
	for i, group := range user.groups {
		groups[i] = toGroupWire(group)
	}
	return userWire{ID: user.ID(), Namespace: user.namespace.Segments(), Groups: groups}
}

func toGroupWire(group Group) groupWire {
	return groupWire{ID: group.ID(), Namespace: group.namespace.Segments()}
}

func toActionWire(action Action) actionWire {
	return actionWire{ID: action.ID(), Namespace: action.namespace.Segments()}
}

func toResourceWire(resource Resource) resourceWire {
	return resourceWire{Kind: resource.kind.String(), ID: resource.ID(), Attrs: toAttrMapWire(resource.attrs)}
}

func toAttrMapWire(values map[string]AttrValue) map[string]attrValueWire {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]attrValueWire, len(values))
	for name, value := range values {
		result[name] = toAttrValueWire(value)
	}
	return result
}

func toAttrValueWire(value AttrValue) attrValueWire {
	if value.typeName != AttrTypeSet {
		return attrValueWire{Type: value.typeName, Value: value.value}
	}
	values, _ := value.value.([]AttrValue)
	set := make([]attrValueWire, len(values))
	for i, item := range values {
		set[i] = toAttrValueWire(item)
	}
	return attrValueWire{Type: AttrTypeSet, Value: set}
}
