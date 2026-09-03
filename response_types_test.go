package treetop

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestBatchResultRequiresValidTaggedShape(t *testing.T) {
	tests := []string{
		`{"status":"success"}`,
		`{"status":"failed"}`,
		`{"status":"future","error":"nope"}`,
		`{"status":"success","result":null}`,
	}
	for _, input := range tests {
		var result IndexedResult[AuthorizeDecisionBrief]
		err := json.Unmarshal([]byte(input), &result)
		var invalid *InvalidResponseError
		if !errors.As(err, &invalid) {
			t.Errorf("input %s: got %T %v, want *InvalidResponseError", input, err, err)
		}
	}
}

func TestMetadataSourceCurrentAndLegacyShapes(t *testing.T) {
	for _, input := range []string{`{"url":"https://example.com/policies"}`, `"https://example.com/legacy"`} {
		var source MetadataSource
		if err := json.Unmarshal([]byte(input), &source); err != nil {
			t.Fatalf("decode %s: %v", input, err)
		}
		if source.URL == "" {
			t.Fatal("source URL is empty")
		}
	}
}

func TestStatusAppliesLegacyDefaults(t *testing.T) {
	input := `{
		"policy_configuration":{"allow_upload":false,"policies":{},"labels":{}},
		"parallel_configuration":{}
	}`
	var status StatusResponse
	if err := json.Unmarshal([]byte(input), &status); err != nil {
		t.Fatal(err)
	}
	if status.RequestLimits != DefaultRequestLimits() {
		t.Fatalf("got %#v, want default request limits", status.RequestLimits)
	}
	if status.RequestContext.Supported {
		t.Fatal("legacy response must not claim context support")
	}
}

func TestAuthorizeResponseValidateRejectsNegativeExpectedCount(t *testing.T) {
	response := &AuthorizeBriefResponse{}
	var validation *ValidationError
	if err := response.Validate(-1); !errors.As(err, &validation) {
		t.Fatalf("got %T %v, want *ValidationError", err, err)
	}
}
