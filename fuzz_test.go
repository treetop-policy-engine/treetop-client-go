package treetop

import (
	"encoding/json"
	"testing"
)

func FuzzAttrValueJSON(f *testing.F) {
	f.Add(`{"type":"String","value":"hello"}`)
	f.Add(`{"type":"Set","value":[{"type":"Long","value":1}]}`)
	f.Add(`{"type":"Future","value":null}`)
	f.Fuzz(func(t *testing.T, input string) {
		var value AttrValue
		if json.Unmarshal([]byte(input), &value) == nil {
			if err := value.Validate(); err != nil {
				t.Fatalf("successful decode produced invalid value: %v", err)
			}
		}
	})
}

func FuzzPrincipalJSON(f *testing.F) {
	f.Add(`{"User":{"id":"alice","namespace":[],"groups":[]}}`)
	f.Add(`{"Group":{"id":"admins","namespace":[]}}`)
	f.Add(`{"Future":{}}`)
	f.Fuzz(func(t *testing.T, input string) {
		var principal Principal
		if json.Unmarshal([]byte(input), &principal) == nil {
			if err := principal.Validate(); err != nil {
				t.Fatalf("successful decode produced invalid principal: %v", err)
			}
		}
	})
}

func FuzzBaseURL(f *testing.F) {
	f.Add("https://example.com")
	f.Add("http://localhost:9999/prefix")
	f.Add("https://user:secret@example.com")
	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := parseBaseURL(input)
		if err == nil {
			if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				t.Fatalf("successful parse violated base URL invariants: %s", parsed)
			}
		}
	})
}

func FuzzAuthorizationResultJSON(f *testing.F) {
	f.Add(`{"index":0,"status":"failed","error":"bad input"}`)
	f.Add(`{"index":0,"status":"success","result":{"decision":"Deny","policy_id":"","version":{"hash":"abc","loaded_at":"2026-09-03T07:00:00Z"}}}`)
	f.Fuzz(func(t *testing.T, input string) {
		var result IndexedResult[AuthorizeDecisionBrief]
		_ = json.Unmarshal([]byte(input), &result)
	})
}
