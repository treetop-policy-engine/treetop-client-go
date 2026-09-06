package treetop

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func BenchmarkAuthorizationResponseParsing(b *testing.B) {
	for _, size := range []int{1, 128} {
		b.Run(fmt.Sprintf("batch-%d", size), func(b *testing.B) {
			version := `{"hash":"abc","loaded_at":"` + testLoadedAt + `","label_set":"labels-v1","generation":7}`
			items := make([]string, size)
			for i := range items {
				items[i] = fmt.Sprintf(`{"index":%d,"status":"success","result":{"decision":"Deny","policy_id":"","version":%s}}`, i, version)
			}
			data := []byte(fmt.Sprintf(`{"results":[%s],"version":%s,"successful":%d,"failed":0}`, strings.Join(items, ","), version, size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var response AuthorizeBriefResponse
				if err := json.Unmarshal(data, &response); err != nil {
					b.Fatal(err)
				}
				if err := response.Validate(size); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

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
