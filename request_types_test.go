package treetop

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestAuthorizationRequestWireFormat(t *testing.T) {
	request := testRequest(t)
	authRequest, err := NewAuthRequest(request,
		WithRequestID("check-1"),
		WithContext(map[string]AttrValue{"env": StringValue("prod")}),
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := NewAuthorizeRequest(authRequest)
	if err != nil {
		t.Fatal(err)
	}

	got, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"requests":[{"id":"check-1","context":{"env":{"type":"String","value":"prod"}},"principal":{"User":{"id":"alice","namespace":[],"groups":[{"id":"admins","namespace":[]}]}},"action":{"id":"view","namespace":[]},"resource":{"kind":"Document","id":"doc-42","attrs":{"owner":{"type":"String","value":"alice"}}}}]}`
	if string(got) != want {
		t.Fatalf("wire format mismatch\n got: %s\nwant: %s", got, want)
	}

	var roundTrip AuthorizeRequest
	if err := json.Unmarshal(got, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConstructorsRejectUnsafeValues(t *testing.T) {
	tests := []struct {
		name string
		make func() error
	}{
		{"quoted user", func() error { _, err := NewUser(`bad"id`); return err }},
		{"reserved namespace", func() error { _, err := NewNamespace("__cedar"); return err }},
		{"reserved Cedar keyword", func() error { _, err := NewNamespace("if"); return err }},
		{"invalid resource kind", func() error { _, err := NewEntityType("not-a-kind"); return err }},
		{"invalid IP", func() error { _, err := IPValue("999.1.1.1"); return err }},
		{"control in request ID", func() error { return WithRequestID("bad\nid")(&AuthRequest{}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var validation *ValidationError
			if err := test.make(); !errors.As(err, &validation) {
				t.Fatalf("got %T %v, want *ValidationError", err, err)
			}
		})
	}
}

func TestJSONDecodingRequiresRequestDomainFields(t *testing.T) {
	tests := []struct {
		name   string
		decode func() error
	}{
		{"group ID", func() error { var value Group; return json.Unmarshal([]byte(`{"namespace":[]}`), &value) }},
		{"group namespace", func() error { var value Group; return json.Unmarshal([]byte(`{"id":"admins"}`), &value) }},
		{"user ID", func() error { var value User; return json.Unmarshal([]byte(`{"namespace":[],"groups":[]}`), &value) }},
		{"user namespace", func() error { var value User; return json.Unmarshal([]byte(`{"id":"alice","groups":[]}`), &value) }},
		{"user groups", func() error { var value User; return json.Unmarshal([]byte(`{"id":"alice","namespace":[]}`), &value) }},
		{"action ID", func() error { var value Action; return json.Unmarshal([]byte(`{"namespace":[]}`), &value) }},
		{"action namespace", func() error { var value Action; return json.Unmarshal([]byte(`{"id":"view"}`), &value) }},
		{"resource kind", func() error { var value Resource; return json.Unmarshal([]byte(`{"id":"one"}`), &value) }},
		{"resource ID", func() error { var value Resource; return json.Unmarshal([]byte(`{"kind":"Document"}`), &value) }},
		{"empty optional request ID", func() error {
			var value AuthRequest
			return json.Unmarshal([]byte(`{
				"id":"",
				"principal":{"User":{"id":"alice","namespace":[],"groups":[]}},
				"action":{"id":"view","namespace":[]},
				"resource":{"kind":"Document","id":"doc-42"}
			}`), &value)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var validation *ValidationError
			if err := test.decode(); !errors.As(err, &validation) {
				t.Fatalf("got %T %v, want *ValidationError", err, err)
			}
		})
	}
}

func TestAuthorizeRequestRejectsDuplicateIDs(t *testing.T) {
	first, err := NewAuthRequest(testRequest(t), WithRequestID("same"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAuthRequest(testRequest(t), WithRequestID("same"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewAuthorizeRequest(first, second)
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("got %T %v, want *ValidationError", err, err)
	}
}

func TestContextLimits(t *testing.T) {
	withoutContext, err := RequestsBatch(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	tiny := DefaultRequestLimits()
	tiny.MaxContextBytes = 1
	if err := withoutContext.validateLimits(tiny); err != nil {
		t.Fatalf("empty context consumed the context limit: %v", err)
	}

	authRequest, err := NewAuthRequest(testRequest(t), WithContext(map[string]AttrValue{
		"nested": SetValue(SetValue(StringValue("value"))),
	}))
	if err != nil {
		t.Fatal(err)
	}
	batch, err := NewAuthorizeRequest(authRequest)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultRequestLimits()
	limits.MaxContextDepth = 2
	if err := batch.validateLimits(limits); err == nil {
		t.Fatal("expected nested context to exceed the limit")
	}

	limits = DefaultRequestLimits()
	limits.MaxContextBytes = 8
	if err := batch.validateLimits(limits); err == nil {
		t.Fatal("expected serialized context to exceed the limit")
	}
}

func TestAttrValueRoundTrip(t *testing.T) {
	ip, err := IPValue("2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	want := SetValue(StringValue("a"), BoolValue(true), LongValue(-4), ip)
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got AttrValue
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type() != AttrTypeSet || len(got.Value().([]AttrValue)) != 4 {
		t.Fatalf("unexpected round trip value: %#v", got.Value())
	}
}

func TestEmptySetUsesArrayAndNullAttributesAreRejected(t *testing.T) {
	data, err := json.Marshal(SetValue())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), `{"type":"Set","value":[]}`; got != want {
		t.Fatalf("empty set wire format = %s, want %s", got, want)
	}

	for _, kind := range []AttrType{AttrTypeString, AttrTypeBool, AttrTypeLong, AttrTypeIP, AttrTypeSet} {
		t.Run(string(kind), func(t *testing.T) {
			for _, value := range []string{"null", "missing"} {
				input := `{"type":"` + string(kind) + `","value":null}`
				if value == "missing" {
					input = `{"type":"` + string(kind) + `"}`
				}
				var decoded AttrValue
				var validation *ValidationError
				if err := json.Unmarshal([]byte(input), &decoded); !errors.As(err, &validation) {
					t.Errorf("%s value: got %T %v, want *ValidationError", value, err, err)
				}
			}
		})
	}
}

func TestUserInGroupsAcceptsMultipleAndComposes(t *testing.T) {
	user, err := NewUser("alice", UserInGroups("admins", "operators"), UserWithGroupNames("auditors"))
	if err != nil {
		t.Fatal(err)
	}
	groups := user.Groups()
	if len(groups) != 3 || groups[0].ID() != "admins" || groups[1].ID() != "operators" || groups[2].ID() != "auditors" {
		t.Fatalf("unexpected groups: %#v", groups)
	}
}

func testRequest(t *testing.T) Request {
	t.Helper()
	user, err := NewUser("alice", UserWithGroupNames("admins"))
	if err != nil {
		t.Fatal(err)
	}
	action, err := NewAction("view")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := NewResource("Document", "doc-42", ResourceWithAttribute("owner", StringValue("alice")))
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest(UserPrincipal(user), action, resource)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testNamespace(t *testing.T, segments ...string) Namespace {
	t.Helper()
	namespace, err := NewNamespace(segments...)
	if err != nil {
		t.Fatal(err)
	}
	return namespace
}
