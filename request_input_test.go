package treetop

import (
	"errors"
	"testing"
)

func TestNewRequestFromRawInput(t *testing.T) {
	request, err := NewRequestFrom(RequestInput{
		Principal: UserInput{
			Name:       "alice",
			Namespace:  []string{"Application"},
			GroupNames: []string{"admins"},
			Groups:     []GroupInput{{Name: "operators", Namespace: []string{"Application"}}},
		},
		Action:          "view",
		ActionNamespace: []string{"Application"},
		Resource: ResourceInput{
			Type:       "Application::Document",
			ID:         "doc-42",
			Attributes: map[string]AttrValue{"owner": StringValue("alice")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, ok := request.Principal().User()
	if !ok || user.Namespace().String() != "Application" || len(user.Groups()) != 2 {
		t.Fatalf("unexpected user principal: %#v", request.Principal())
	}
	if request.Action().Namespace().String() != "Application" || request.Resource().Kind().String() != "Application::Document" {
		t.Fatalf("unexpected request: %#v", request)
	}
	if _, ok := request.Resource().Attribute("owner"); !ok {
		t.Fatal("resource attribute is missing")
	}
}

func TestNewRequestFromAcceptsGroupPrincipal(t *testing.T) {
	request, err := NewRequestFrom(RequestInput{
		Principal: GroupInput{Name: "admins"},
		Action:    "audit",
		Resource:  ResourceInput{Type: "Log", ID: "today"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if group, ok := request.Principal().Group(); !ok || group.ID() != "admins" {
		t.Fatalf("unexpected group principal: %#v", request.Principal())
	}
}

func TestNewRequestFromAggregatesInvalidRawFields(t *testing.T) {
	_, err := NewRequestFrom(RequestInput{
		Principal: UserInput{Name: `bad"id`},
		Action:    "bad\nid",
		Resource:  ResourceInput{Type: "123Document", ID: "doc-42"},
	})
	var buildError *RequestBuildError
	if !errors.As(err, &buildError) || len(buildError.Errors()) != 3 {
		t.Fatalf("got %T %v, want three-field *RequestBuildError", err, err)
	}
}

func TestNewResourceAcceptsStringAndTypedEntityType(t *testing.T) {
	fromString, err := NewResource("Document", "doc-42")
	if err != nil {
		t.Fatal(err)
	}
	typed, err := NewEntityType("Document")
	if err != nil {
		t.Fatal(err)
	}
	fromType, err := NewResourceWithType(typed, "doc-42")
	if err != nil {
		t.Fatal(err)
	}
	if fromString.Kind() != fromType.Kind() || fromString.ID() != fromType.ID() {
		t.Fatalf("resource constructors differ: %#v != %#v", fromString, fromType)
	}
}
