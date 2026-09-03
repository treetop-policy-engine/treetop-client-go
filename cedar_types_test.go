package treetop_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	treetop "github.com/treetop-policy-engine/treetop-client-go"
)

func TestRequestDomainRepresentationsAreOpaque(t *testing.T) {
	values := []any{
		treetop.Namespace{},
		treetop.EntityType{},
		treetop.Group{},
		treetop.User{},
		treetop.Principal{},
		treetop.Action{},
		treetop.AttrValue{},
		treetop.Resource{},
		treetop.Request{},
		treetop.AuthRequest{},
		treetop.AuthorizeRequest{},
	}
	for _, value := range values {
		typeOf := reflect.TypeOf(value)
		for i := 0; i < typeOf.NumField(); i++ {
			if typeOf.Field(i).IsExported() {
				t.Errorf("%s.%s exposes request state", typeOf.Name(), typeOf.Field(i).Name)
			}
		}
	}
}

func TestNamespaceConstructionAndJSON(t *testing.T) {
	segments := []string{"MyApp", "Core"}
	namespace, err := treetop.NewNamespace(segments...)
	if err != nil {
		t.Fatal(err)
	}
	segments[0] = "Changed"
	if namespace.String() != "MyApp::Core" {
		t.Fatalf("namespace changed through constructor input: %q", namespace)
	}

	returned := namespace.Segments()
	returned[0] = "Changed"
	if namespace.String() != "MyApp::Core" {
		t.Fatalf("namespace changed through Segments result: %q", namespace)
	}

	encoded, err := json.Marshal(namespace)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `["MyApp","Core"]` {
		t.Fatalf("namespace JSON = %s", encoded)
	}

	parsed, err := treetop.ParseNamespace("MyApp::Core")
	if err != nil {
		t.Fatal(err)
	}
	if parsed != namespace {
		t.Fatalf("parsed namespace = %q, want %q", parsed, namespace)
	}

	var decoded treetop.Namespace
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != namespace {
		t.Fatalf("decoded namespace = %q, want %q", decoded, namespace)
	}

	globalJSON, err := json.Marshal(treetop.Namespace{})
	if err != nil {
		t.Fatal(err)
	}
	if string(globalJSON) != `[]` {
		t.Fatalf("global namespace JSON = %s", globalJSON)
	}
}

func TestNamespaceRejectsInvalidRepresentations(t *testing.T) {
	for _, test := range []struct {
		name string
		make func() error
	}{
		{name: "reserved", make: func() error { _, err := treetop.NewNamespace("__cedar"); return err }},
		{name: "empty segment", make: func() error { _, err := treetop.ParseNamespace("App::::Core"); return err }},
		{name: "null JSON", make: func() error {
			var namespace treetop.Namespace
			return json.Unmarshal([]byte(`null`), &namespace)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var validation *treetop.ValidationError
			if err := test.make(); !errors.As(err, &validation) {
				t.Fatalf("got %T %v, want *ValidationError", err, err)
			}
		})
	}
}

func TestEntityTypeConstructionAndJSON(t *testing.T) {
	entityType, err := treetop.NewEntityType("MyApp::Document")
	if err != nil {
		t.Fatal(err)
	}
	if entityType.String() != "MyApp::Document" {
		t.Fatalf("entity type = %q", entityType)
	}
	encoded, err := json.Marshal(entityType)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `"MyApp::Document"` {
		t.Fatalf("entity type JSON = %s", encoded)
	}

	var decoded treetop.EntityType
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != entityType {
		t.Fatalf("decoded entity type = %q, want %q", decoded, entityType)
	}
	if _, err := json.Marshal(treetop.EntityType{}); err == nil {
		t.Fatal("zero entity type unexpectedly encoded")
	}
}

func TestRequestDomainValuesAreImmutable(t *testing.T) {
	namespace, err := treetop.NewNamespace("MyApp")
	if err != nil {
		t.Fatal(err)
	}
	group, err := treetop.NewGroup("admins", treetop.GroupWithNamespace(namespace))
	if err != nil {
		t.Fatal(err)
	}
	user, err := treetop.NewUser("alice", treetop.UserWithNamespace(namespace), treetop.UserWithGroups(group))
	if err != nil {
		t.Fatal(err)
	}
	action, err := treetop.NewAction("view", treetop.ActionWithNamespace(namespace))
	if err != nil {
		t.Fatal(err)
	}
	resourceType, err := treetop.NewEntityType("MyApp::Document")
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]treetop.AttrValue{"owner": treetop.StringValue("alice")}
	resource, err := treetop.NewResourceWithType(resourceType, "doc-42", treetop.ResourceWithAttributes(attrs))
	if err != nil {
		t.Fatal(err)
	}
	delete(attrs, "owner")
	if _, ok := resource.Attribute("owner"); !ok {
		t.Fatal("resource changed through constructor input")
	}
	returnedAttrs := resource.Attributes()
	delete(returnedAttrs, "owner")
	if _, ok := resource.Attribute("owner"); !ok {
		t.Fatal("resource changed through Attributes result")
	}

	groups := user.Groups()
	groups[0] = treetop.Group{}
	if err := user.Validate(); err != nil {
		t.Fatalf("user changed through Groups result: %v", err)
	}
	principal := treetop.UserPrincipal(user)
	request, err := treetop.NewRequest(principal, action, resource)
	if err != nil {
		t.Fatal(err)
	}
	contextValues := map[string]treetop.AttrValue{"environment": treetop.StringValue("production")}
	item, err := treetop.NewAuthRequest(request, treetop.WithRequestID("check-1"), treetop.WithContext(contextValues))
	if err != nil {
		t.Fatal(err)
	}
	delete(contextValues, "environment")
	returnedContext := item.Context()
	delete(returnedContext, "environment")
	if len(item.Context()) != 1 {
		t.Fatal("authorization item context was externally mutated")
	}
	batch, err := treetop.NewAuthorizeRequest(item)
	if err != nil {
		t.Fatal(err)
	}
	items := batch.Requests()
	items[0] = treetop.AuthRequest{}
	if err := batch.Validate(); err != nil {
		t.Fatalf("batch changed through Requests result: %v", err)
	}

	if group.ID() != "admins" || group.Namespace() != namespace {
		t.Fatal("group accessors returned unexpected values")
	}
	if user.ID() != "alice" || user.Namespace() != namespace {
		t.Fatal("user accessors returned unexpected values")
	}
	if action.ID() != "view" || action.Namespace() != namespace {
		t.Fatal("action accessors returned unexpected values")
	}
	if resource.ID() != "doc-42" || resource.Kind() != resourceType {
		t.Fatal("resource accessors returned unexpected values")
	}
	if _, ok := principal.User(); !ok {
		t.Fatal("user principal did not expose its user")
	}
	if _, ok := principal.Group(); ok {
		t.Fatal("user principal unexpectedly exposed a group")
	}
	if _, ok := request.Principal().User(); !ok || request.Action() != action || request.Resource().ID() != resource.ID() {
		t.Fatal("request accessors returned unexpected values")
	}
	if id, ok := item.ID(); !ok || id != "check-1" {
		t.Fatalf("authorization item ID = %q, %t", id, ok)
	}
	if item.Request().Resource().ID() != resource.ID() || batch.Len() != 1 {
		t.Fatal("authorization request accessors returned unexpected values")
	}
}

func TestZeroRequestDomainValuesAreRejected(t *testing.T) {
	for _, value := range []interface{ Validate() error }{
		treetop.Group{},
		treetop.User{},
		treetop.Action{},
		treetop.Resource{},
		treetop.Principal{},
		treetop.Request{},
		treetop.AuthRequest{},
	} {
		if err := value.Validate(); err == nil {
			t.Fatalf("%T zero value unexpectedly validated", value)
		}
	}

	var emptyBatch treetop.AuthorizeRequest
	if err := emptyBatch.Validate(); err != nil {
		t.Fatalf("empty authorization batch should be a valid zero value: %v", err)
	}
	encoded, err := json.Marshal(emptyBatch)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"requests":[]}` {
		t.Fatalf("empty authorization batch JSON = %s", encoded)
	}
}
