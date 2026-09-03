package treetop

import (
	"encoding/json"
	"fmt"
	"testing"
)

func BenchmarkAuthorizationRequestEncoding(b *testing.B) {
	for _, size := range []int{1, 32, 1024} {
		b.Run(fmt.Sprintf("batch-%d", size), func(b *testing.B) {
			request := benchmarkAuthorizationRequest(b, size)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := encodeJSONBounded(toAuthorizeRequestWire(request), defaultMaxBodyBytes); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAuthorizationRequestMarshalJSON(b *testing.B) {
	request := benchmarkAuthorizationRequest(b, 32)
	b.ReportAllocs()
	for range b.N {
		if _, err := json.Marshal(request); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkAuthorizationRequest(tb testing.TB, size int) *AuthorizeRequest {
	tb.Helper()
	user, err := NewUser("alice", UserInGroups("admins", "operators"))
	if err != nil {
		tb.Fatal(err)
	}
	action, err := NewAction("view")
	if err != nil {
		tb.Fatal(err)
	}
	resource, err := NewResource("Document", "doc-42",
		ResourceWithAttribute("owner", StringValue("alice")),
		ResourceWithAttribute("tags", SetValue(StringValue("production"), StringValue("web"))),
	)
	if err != nil {
		tb.Fatal(err)
	}
	request, err := NewRequest(UserPrincipal(user), action, resource)
	if err != nil {
		tb.Fatal(err)
	}
	items := make([]AuthRequest, size)
	for i := range items {
		items[i], err = NewAuthRequest(request,
			WithRequestID(fmt.Sprintf("request-%d", i)),
			WithContext(map[string]AttrValue{"depth": SetValue(SetValue(StringValue("value")))}),
		)
		if err != nil {
			tb.Fatal(err)
		}
	}
	batch, err := NewAuthorizeRequest(items...)
	if err != nil {
		tb.Fatal(err)
	}
	return batch
}
