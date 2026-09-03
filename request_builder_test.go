package treetop

import (
	"errors"
	"testing"
)

func TestRequestBuilderBuildsCommonUserRequest(t *testing.T) {
	request, err := NewRequestBuilder().
		User("alice", UserInGroups("admins", "operators")).
		Action("view").
		Resource("Document", "doc-42", ResourceWithAttribute("owner", StringValue("alice"))).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if request.Action().ID() != "view" || request.Resource().Kind().String() != "Document" {
		t.Fatalf("unexpected request: %#v", request)
	}
	user, ok := request.Principal().User()
	if !ok || len(user.Groups()) != 2 {
		t.Fatalf("unexpected principal: %#v", request.Principal())
	}
}

func TestRequestBuilderSupportsGroupPrincipal(t *testing.T) {
	request, err := NewRequestBuilder().Group("admins").Action("audit").Resource("Log", "today").Build()
	if err != nil {
		t.Fatal(err)
	}
	if group, ok := request.Principal().Group(); !ok || group.ID() != "admins" {
		t.Fatalf("unexpected principal: %#v", request.Principal())
	}
}

func TestRequestBuilderReportsErrors(t *testing.T) {
	tests := []struct {
		name    string
		builder *RequestBuilder
	}{
		{"missing field", NewRequestBuilder().User("alice").Action("view")},
		{"invalid user", NewRequestBuilder().User(`bad"id`).Action("view").Resource("Document", "one")},
		{"duplicate principal", NewRequestBuilder().User("alice").Group("admins").Action("view").Resource("Document", "one")},
		{"duplicate action", NewRequestBuilder().User("alice").Action("view").Action("edit").Resource("Document", "one")},
		{"duplicate resource", NewRequestBuilder().User("alice").Action("view").Resource("Document", "one").Resource("Document", "two")},
		{"nil builder", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.builder.Build()
			var configuration *ConfigurationError
			var validation *ValidationError
			if !errors.As(err, &configuration) && !errors.As(err, &validation) {
				t.Fatalf("got %T %v, want configuration or validation error", err, err)
			}
		})
	}
}

func TestRequestBuilderAggregatesIndependentValidationErrors(t *testing.T) {
	_, err := NewRequestBuilder().User(`bad"id`).Action("bad\nid").Resource("123Document", "doc-42").Build()
	var buildError *RequestBuildError
	if !errors.As(err, &buildError) {
		t.Fatalf("got %T %v, want *RequestBuildError", err, err)
	}
	if got := len(buildError.Errors()); got != 3 {
		t.Fatalf("got %d field errors, want 3: %v", got, err)
	}
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("aggregate does not unwrap validation errors: %v", err)
	}
}
