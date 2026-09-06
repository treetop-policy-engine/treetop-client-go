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

func TestPolicyVersionMetadataRoundTripAndLegacyDefaults(t *testing.T) {
	for _, test := range []struct {
		extra      string
		generation uint64
		labels     string
	}{
		{"", 0, ""},
		{`,"label_set":null,"generation":0`, 0, ""},
		{`,"label_set":"labels-v2","generation":18446744073709551615`, ^uint64(0), "labels-v2"},
	} {
		input := `{"hash":"abc","loaded_at":"` + testLoadedAt + `"` + test.extra + `}`
		var version PolicyVersion
		if err := json.Unmarshal([]byte(input), &version); err != nil {
			t.Fatal(err)
		}
		if version.Generation != test.generation {
			t.Fatalf("got generation %d, want %d", version.Generation, test.generation)
		}
		if test.labels == "" && version.LabelSet != nil || test.labels != "" && (version.LabelSet == nil || *version.LabelSet != test.labels) {
			t.Fatal("incorrect label identifier")
		}
		encoded, err := json.Marshal(version)
		if err != nil {
			t.Fatal(err)
		}
		var restored PolicyVersion
		if err := json.Unmarshal(encoded, &restored); err != nil {
			t.Fatal(err)
		}
		if !version.equal(restored) {
			t.Fatalf("lost metadata: %s", encoded)
		}
	}
}

func TestPolicyVersionRejectsInvalidGeneration(t *testing.T) {
	for _, generation := range []string{"null", "-1", "18446744073709551616", "true", "false", "1.5", "1e3", `"1"`} {
		var version PolicyVersion
		if err := json.Unmarshal([]byte(`{"generation":`+generation+`}`), &version); err == nil {
			t.Errorf("accepted generation %s", generation)
		}
	}
}

func TestBatchesCompareCompletePolicyVersion(t *testing.T) {
	batchVersion := `{"hash":"abc","loaded_at":"` + testLoadedAt + `","label_set":"labels-v1","generation":1}`
	for _, test := range []struct {
		name, itemVersion string
		valid             bool
	}{
		{"equal values in separate allocations", batchVersion, true},
		{"changed labels", `{"hash":"abc","loaded_at":"` + testLoadedAt + `","label_set":"labels-v2","generation":1}`, false},
		{"missing labels", `{"hash":"abc","loaded_at":"` + testLoadedAt + `","label_set":null,"generation":1}`, false},
		{"changed generation", `{"hash":"abc","loaded_at":"` + testLoadedAt + `","label_set":"labels-v1","generation":2}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := `{"results":[{"index":0,"status":"success","result":{"decision":"Deny","policy":[],"policy_id":"","version":` + test.itemVersion + `}}],"version":` + batchVersion + `,"successful":1,"failed":0}`
			var brief AuthorizeBriefResponse
			var detailed AuthorizeDetailedResponse
			if err := json.Unmarshal([]byte(input), &brief); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(input), &detailed); err != nil {
				t.Fatal(err)
			}
			for _, err := range []error{brief.Validate(1), detailed.Validate(1)} {
				if test.valid && err != nil {
					t.Fatal(err)
				}
				if !test.valid {
					var invalid *InvalidResponseError
					if !errors.As(err, &invalid) {
						t.Fatalf("expected version mismatch, got %v", err)
					}
				}
			}
		})
	}
}

func TestBatchesRejectNullGeneration(t *testing.T) {
	validVersion := `{"hash":"abc","loaded_at":"` + testLoadedAt + `","generation":0}`
	nullVersion := `{"hash":"abc","loaded_at":"` + testLoadedAt + `","generation":null}`
	for _, versions := range [][2]string{{nullVersion, validVersion}, {validVersion, nullVersion}} {
		input := `{"results":[{"index":0,"status":"success","result":{"decision":"Deny","policy":[],"policy_id":"","version":` + versions[0] + `}}],"version":` + versions[1] + `,"successful":1,"failed":0}`
		var brief AuthorizeBriefResponse
		var detailed AuthorizeDetailedResponse
		for _, err := range []error{json.Unmarshal([]byte(input), &brief), json.Unmarshal([]byte(input), &detailed)} {
			var invalid *InvalidResponseError
			if !errors.As(err, &invalid) {
				t.Fatalf("expected invalid generation, got %v", err)
			}
		}
	}
}
