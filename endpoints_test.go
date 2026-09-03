package treetop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadEndpointsAndDetailedAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/version":
			_, _ = io.WriteString(response, `{"version":"0.0.15","core":{"version":"0.1.0","cedar":"4.4.2"},"policies":{"hash":"abc","loaded_at":"`+testLoadedAt+`"},"schema":{"hash":"def","loaded_at":"`+testLoadedAt+`"}}`)
		case "/api/v1/status":
			_, _ = io.WriteString(response, `{
				"policy_configuration":{"allow_upload":true,"schema_validation_mode":"strict",
				"policies":{"timestamp":"`+testLoadedAt+`","sha256":"abc","size":10,"entries":1,"content":"permit();"},
				"labels":{"timestamp":"`+testLoadedAt+`","sha256":"def","size":2,"entries":0,"content":"{}"},
				"schema":{"timestamp":"`+testLoadedAt+`","sha256":"ghi","size":2,"entries":1,"content":"{}"},
				"bundle":{"format_version":1,"bundle_id":"bundle","archive_sha256":"sum","compressed_size":12,"module_count":2,"signed":true,"signing_key_id":"key-1","loaded_at":"`+testLoadedAt+`"}},
				"parallel_configuration":{"cpu_count":8,"workers":4,"rayon_threads":4,"par_threshold":8,"allow_parallel":true},
				"request_limits":{"max_batch_size":1024,"max_context_bytes":16384,"max_context_depth":8,"max_context_keys":64},
				"request_context":{"supported":true,"schema_backed":true}}`)
		case "/api/v1/policies":
			if request.URL.Query().Get("format") == "raw" {
				response.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(response, "permit();")
			} else {
				_, _ = io.WriteString(response, `{"policies":{"timestamp":"`+testLoadedAt+`","sha256":"abc","size":10,"source":{"url":"https://example.com/policies"},"entries":1,"content":"permit();"}}`)
			}
		case "/api/v1/schema":
			if request.URL.Query().Get("format") == "raw" {
				response.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(response, "{}")
			} else {
				_, _ = io.WriteString(response, `{"schema":{"timestamp":"`+testLoadedAt+`","sha256":"def","size":2,"entries":1,"content":"{}"}}`)
			}
		case "/api/v1/policies/alice":
			if request.URL.Query().Get("format") == "raw" {
				response.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(response, "permit();")
			} else {
				_, _ = io.WriteString(response, `{"user":"alice","policies":[{"effect":"permit"}],"matches":[{"cedar_id":"policy0","reasons":["FutureReason"]}]}`)
			}
		case "/api/v1/authorize":
			if request.URL.Query().Get("detail") != "full" {
				t.Errorf("detail = %q", request.URL.Query().Get("detail"))
			}
			_, _ = io.WriteString(response, `{
				"results":[{"index":0,"status":"success","result":{"decision":"Allow","policy":[{"literal":"permit();","json":{"effect":"permit"},"cedar_id":"policy0"}],"version":{"hash":"abc","loaded_at":"`+testLoadedAt+`"}}}],
				"version":{"hash":"abc","loaded_at":"`+testLoadedAt+`"},"successful":1,"failed":0}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	version, err := client.Version(ctx)
	if err != nil || version.Version != "0.0.15" || version.Schema == nil {
		t.Fatalf("Version: %#v, %v", version, err)
	}
	status, err := client.Status(ctx)
	if err != nil || status.PolicyConfiguration.Bundle == nil || status.RequestLimits.MaxBatchSize != 1024 {
		t.Fatalf("Status: %#v, %v", status, err)
	}
	policies, err := client.Policies(ctx)
	if err != nil || policies.Policies.Source == nil {
		t.Fatalf("Policies: %#v, %v", policies, err)
	}
	if text, err := client.PoliciesText(ctx); err != nil || text != "permit();" {
		t.Fatalf("PoliciesText = %q, %v", text, err)
	}
	if schema, err := client.Schema(ctx); err != nil || schema.Schema.SHA256 != "def" {
		t.Fatalf("Schema: %#v, %v", schema, err)
	}
	if text, err := client.SchemaText(ctx); err != nil || text != "{}" {
		t.Fatalf("SchemaText = %q, %v", text, err)
	}
	userPolicies, err := client.UserPolicies(ctx, "alice")
	if err != nil || len(userPolicies.Policies) != 1 || userPolicies.Matches[0].Reasons[0] != "FutureReason" {
		t.Fatalf("UserPolicies: %#v, %v", userPolicies, err)
	}
	if text, err := client.UserPoliciesText(ctx, "alice"); err != nil || text != "permit();" {
		t.Fatalf("UserPoliciesText = %q, %v", text, err)
	}
	batch, err := RequestsBatch(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	detailed, err := client.AuthorizeDetailed(ctx, batch)
	if err != nil || len(detailed.Results[0].Result.Policies) != 1 {
		t.Fatalf("AuthorizeDetailed: %#v, %v", detailed, err)
	}
}

func TestAllUploadRepresentations(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		switch calls {
		case 1:
			if request.URL.Path != "/api/v1/policies" || request.Header.Get("Content-Type") != "text/plain" || string(body) != "permit();" {
				t.Errorf("raw policies request: %s %s %q", request.URL.Path, request.Header.Get("Content-Type"), body)
			}
		case 2:
			if request.URL.Path != "/api/v1/policies" || request.Header.Get("Content-Type") != "application/json" || !json.Valid(body) {
				t.Errorf("JSON policies request: %s %s %q", request.URL.Path, request.Header.Get("Content-Type"), body)
			}
		case 3:
			if request.URL.Path != "/api/v1/schema" || request.Header.Get("Content-Type") != "text/plain" {
				t.Errorf("raw schema request: %s %s", request.URL.Path, request.Header.Get("Content-Type"))
			}
		case 4, 5:
			if request.URL.Path != "/api/v1/schema" || request.Header.Get("Content-Type") != "application/json" || !json.Valid(body) {
				t.Errorf("JSON schema request: %s %s %q", request.URL.Path, request.Header.Get("Content-Type"), body)
			}
		default:
			t.Errorf("unexpected upload call %d", calls)
		}
		_, _ = io.WriteString(response, testPoliciesMetadataJSON)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	token, err := NewUploadToken("secret")
	if err != nil {
		t.Fatal(err)
	}
	uploader, err := client.Uploader(token)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	operations := []func() error{
		func() error { _, err := uploader.UploadPolicies(ctx, "permit();"); return err },
		func() error { _, err := uploader.UploadPoliciesJSON(ctx, "permit();"); return err },
		func() error { _, err := uploader.UploadSchema(ctx, "{}"); return err },
		func() error { _, err := uploader.UploadSchemaJSON(ctx, "{}"); return err },
		func() error { _, err := uploader.UploadSchemaDocument(ctx, json.RawMessage(`{"":{}}`)); return err },
	}
	for i, operation := range operations {
		if err := operation(); err != nil {
			t.Fatalf("operation %d: %v", i+1, err)
		}
	}
}

func TestIsAllowedReturnsEvaluationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, `{"results":[{"index":0,"status":"failed","error":"invalid entity"}],"version":{"hash":"abc","loaded_at":"`+testLoadedAt+`"},"successful":0,"failed":1}`)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.IsAllowed(context.Background(), testRequest(t))
	var evaluation *EvaluationError
	if !errors.As(err, &evaluation) {
		t.Fatalf("got %T %v, want *EvaluationError", err, err)
	}
}

func TestBaseURLValidation(t *testing.T) {
	for _, value := range []string{"", "ftp://example.com", "https://user@example.com", "https://example.com?q=1", "https://example.com/#fragment"} {
		t.Run(value, func(t *testing.T) {
			_, err := New(value)
			var config *ConfigurationError
			if !errors.As(err, &config) {
				t.Fatalf("got %T %v, want *ConfigurationError", err, err)
			}
		})
	}
}
