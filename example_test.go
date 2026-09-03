package treetop_test

import (
	"encoding/json"
	"fmt"

	treetop "github.com/treetop-policy-engine/treetop-client-go"
)

func ExampleNamespace() {
	namespace, _ := treetop.NewNamespace("MyApp", "Documents")
	resourceType, _ := treetop.NewEntityType("MyApp::Document")

	fmt.Println(namespace.String())
	fmt.Println(resourceType.String())
	// Output:
	// MyApp::Documents
	// MyApp::Document
}

func ExampleNewRequest() {
	user, _ := treetop.NewUser("alice", treetop.UserWithGroupNames("admins"))
	action, _ := treetop.NewAction("view")
	resourceType, _ := treetop.NewEntityType("Document")
	resource, _ := treetop.NewResourceWithType(resourceType, "doc-42",
		treetop.ResourceWithAttribute("owner", treetop.StringValue("alice")),
	)
	request, _ := treetop.NewRequest(treetop.UserPrincipal(user), action, resource)
	batch, _ := treetop.RequestsBatch(request)

	body, _ := json.Marshal(batch)
	fmt.Println(string(body))
	// Output: {"requests":[{"principal":{"User":{"id":"alice","namespace":[],"groups":[{"id":"admins","namespace":[]}]}},"action":{"id":"view","namespace":[]},"resource":{"kind":"Document","id":"doc-42","attrs":{"owner":{"type":"String","value":"alice"}}}}]}
}

func ExampleNewRequestBuilder() {
	request, _ := treetop.NewRequestBuilder().
		User("alice", treetop.UserInGroups("admins", "operators")).
		Action("view").
		Resource("Document", "doc-42").
		Build()

	body, _ := json.Marshal(request)
	fmt.Println(string(body))
	// Output: {"principal":{"User":{"id":"alice","namespace":[],"groups":[{"id":"admins","namespace":[]},{"id":"operators","namespace":[]}]}},"action":{"id":"view","namespace":[]},"resource":{"kind":"Document","id":"doc-42"}}
}

func ExampleNewRequestFrom() {
	request, _ := treetop.NewRequestFrom(treetop.RequestInput{
		Principal: treetop.UserInput{Name: "alice", GroupNames: []string{"admins"}},
		Action:    "view",
		Resource:  treetop.ResourceInput{Type: "Document", ID: "doc-42"},
	})

	fmt.Println(request.Resource().Kind())
	// Output: Document
}
