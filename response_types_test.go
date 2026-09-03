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
	input := `{"policy_configuration":` + testPoliciesMetadataJSON + `,
		"parallel_configuration":{"cpu_count":1,"workers":1,"rayon_threads":1,"par_threshold":8,"allow_parallel":false}}`
	var status StatusResponse
	if err := json.Unmarshal([]byte(input), &status); err != nil {
		t.Fatal(err)
	}
	if status.RequestLimits != legacyRequestLimits() {
		t.Fatalf("got %#v, want legacy request limits", status.RequestLimits)
	}
	if status.RequestContext.Supported {
		t.Fatal("legacy response must not claim context support")
	}
}

func TestDefaultRequestLimitsMatchCurrentServerDefaults(t *testing.T) {
	if got := DefaultRequestLimits(); got.MaxBatchSize != 1024 || got.MaxContextBytes != 16<<10 || got.MaxContextDepth != 8 || got.MaxContextKeys != 64 {
		t.Fatalf("unexpected default request limits: %#v", got)
	}
}

func TestStructuredResponsesRejectMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		decode func() error
	}{
		{"version", func() error { var value VersionInfo; return json.Unmarshal([]byte(`{}`), &value) }},
		{"metadata", func() error { var value Metadata; return json.Unmarshal([]byte(`{}`), &value) }},
		{"policy metadata", func() error { var value PoliciesMetadata; return json.Unmarshal([]byte(`{}`), &value) }},
		{"status", func() error { var value StatusResponse; return json.Unmarshal([]byte(`{}`), &value) }},
		{"policy download", func() error { var value PoliciesDownload; return json.Unmarshal([]byte(`{}`), &value) }},
		{"schema download", func() error { var value SchemaDownload; return json.Unmarshal([]byte(`{}`), &value) }},
		{"user policies", func() error { var value UserPolicies; return json.Unmarshal([]byte(`{}`), &value) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var invalid *InvalidResponseError
			if err := test.decode(); !errors.As(err, &invalid) {
				t.Fatalf("got %T %v, want *InvalidResponseError", err, err)
			}
		})
	}
}

func TestPresentStatusRequestLimitsRequireCurrentFields(t *testing.T) {
	input := `{"policy_configuration":` + testPoliciesMetadataJSON + `,
		"parallel_configuration":{"cpu_count":1,"workers":1,"rayon_threads":1,"par_threshold":8,"allow_parallel":false},
		"request_limits":{}}`
	var status StatusResponse
	var invalid *InvalidResponseError
	if err := json.Unmarshal([]byte(input), &status); !errors.As(err, &invalid) {
		t.Fatalf("got %T %v, want *InvalidResponseError", err, err)
	}
}

func TestAuthorizeResponseValidateRejectsNegativeExpectedCount(t *testing.T) {
	response := &AuthorizeBriefResponse{}
	var validation *ValidationError
	if err := response.Validate(-1); !errors.As(err, &validation) {
		t.Fatalf("got %T %v, want *ValidationError", err, err)
	}
}

func TestDetailedResponseRequiresPolicyJSONObject(t *testing.T) {
	input := `{
		"results":[{"index":0,"status":"success","result":{"decision":"Allow","policy":[
			{"literal":"permit();","json":"not an object","cedar_id":"policy0"}],
			"version":{"hash":"abc","loaded_at":"` + testLoadedAt + `"}}}],
		"version":{"hash":"abc","loaded_at":"` + testLoadedAt + `"},"successful":1,"failed":0}`
	var response AuthorizeDetailedResponse
	if err := json.Unmarshal([]byte(input), &response); err != nil {
		t.Fatal(err)
	}
	var invalid *InvalidResponseError
	if err := response.Validate(1); !errors.As(err, &invalid) {
		t.Fatalf("got %T %v, want *InvalidResponseError", err, err)
	}
}
