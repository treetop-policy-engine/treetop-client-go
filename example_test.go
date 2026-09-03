package treetop_test

import (
	"encoding/json"
	"fmt"

	treetop "github.com/treetop-policy-engine/treetop-client-go"
)

func ExampleNewRequest() {
	user, _ := treetop.NewUser("alice", treetop.UserWithGroupNames("admins"))
	action, _ := treetop.NewAction("view")
	resource, _ := treetop.NewResource("Document", "doc-42",
		treetop.ResourceWithAttribute("owner", treetop.StringValue("alice")),
	)
	request, _ := treetop.NewRequest(treetop.UserPrincipal(user), action, resource)
	batch, _ := treetop.RequestsBatch(request)

	body, _ := json.Marshal(batch)
	fmt.Println(string(body))
	// Output: {"requests":[{"principal":{"User":{"id":"alice","namespace":[],"groups":[{"id":"admins","namespace":[]}]}},"action":{"id":"view","namespace":[]},"resource":{"kind":"Document","id":"doc-42","attrs":{"owner":{"type":"String","value":"alice"}}}}]}
}
