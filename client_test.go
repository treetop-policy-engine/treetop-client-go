package treetop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const testLoadedAt = "2026-09-03T07:00:00Z"

func TestAuthorizeSendsExactContractAndCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.RequestURI() != "/prefix/api/v1/authorize?detail=brief" {
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.RequestURI())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer access-secret" {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("x-correlation-id"); got != "trace-1" {
			t.Errorf("x-correlation-id = %q", got)
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body["requests"]) == 0 {
			t.Error("request body has no requests")
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{
			"results":[{"index":0,"id":"check-1","status":"success","result":{
				"decision":"Allow","version":{"hash":"abc","loaded_at":"`+testLoadedAt+`"},"policy_id":"policy0"}}],
			"version":{"hash":"abc","loaded_at":"`+testLoadedAt+`"},"successful":1,"failed":0}`)
	}))
	defer server.Close()

	access, err := NewAccessToken("access-secret")
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(server.URL+"/prefix", WithAccessToken(access), WithCorrelationID("trace-1"))
	if err != nil {
		t.Fatal(err)
	}
	authRequest, err := NewAuthRequest(testRequest(t), WithRequestID("check-1"))
	if err != nil {
		t.Fatal(err)
	}
	batch, err := NewAuthorizeRequest(authRequest)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Authorize(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if result.Successful != 1 || result.Results[0].Result.Decision != DecisionAllow {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestPublicEndpointsOmitAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		protected := request.URL.Path == "/api/v1/health" || request.URL.Path == "/metrics"
		if got := request.Header.Get("Authorization"); protected && got == "" || !protected && got != "" {
			t.Errorf("path %s has unexpected Authorization %q", request.URL.Path, got)
		}
		switch request.URL.Path {
		case "/openapi.json":
			_, _ = io.WriteString(response, `{}`)
		default:
			_, _ = io.WriteString(response, "ok")
		}
	}))
	defer server.Close()

	token, err := NewAccessToken("secret")
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(server.URL, WithAccessToken(token))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := client.Live(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenAPI(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Metrics(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestReadyMapsServiceUnavailableToFalse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(response, "not ready")
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := client.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ready {
		t.Fatal("expected not ready")
	}
}

func TestClientsDenyRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	for _, test := range []struct {
		name    string
		options []Option
	}{
		{name: "default"},
		{name: "custom client", options: []Option{WithHTTPClient(&http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
		})}},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, err := NewAccessToken("redirect-secret")
			if err != nil {
				t.Fatal(err)
			}
			options := append([]Option{WithAccessToken(token)}, test.options...)
			client, err := New(origin.URL, options...)
			if err != nil {
				t.Fatal(err)
			}
			err = client.Health(context.Background())
			var apiError *APIError
			if !errors.As(err, &apiError) || apiError.StatusCode != http.StatusFound {
				t.Fatalf("got %T %v, want redirect API error", err, err)
			}
			if targetCalls.Load() != 0 {
				t.Fatal("redirect target was contacted")
			}
		})
	}
}

func TestResponseAndRequestLimits(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(response, "response is too large")
	}))
	defer server.Close()
	client, err := New(server.URL, WithMaxResponseBytes(4), WithMaxRequestBytes(16))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Metrics(context.Background())
	var responseTooLarge *ResponseTooLargeError
	if !errors.As(err, &responseTooLarge) {
		t.Fatalf("got %T %v, want *ResponseTooLargeError", err, err)
	}

	batch, err := RequestsBatch(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	err = nil
	_, err = client.Authorize(context.Background(), batch)
	var requestTooLarge *RequestTooLargeError
	if !errors.As(err, &requestTooLarge) {
		t.Fatalf("got %T %v, want *RequestTooLargeError", err, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("oversized request reached server; calls = %d", calls.Load())
	}
}

func TestMalformedAuthorizationResponseIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, `{
			"results":[{"index":0,"status":"success","result":{
				"decision":"Deny","version":{"hash":"abc","loaded_at":"`+testLoadedAt+`"},"policy_id":"policy0"}}],
			"version":{"hash":"abc","loaded_at":"`+testLoadedAt+`"},"successful":1,"failed":0}`)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := RequestsBatch(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Authorize(context.Background(), batch)
	var invalid *InvalidResponseError
	if !errors.As(err, &invalid) {
		t.Fatalf("got %T %v, want *InvalidResponseError", err, err)
	}
}

func TestUserPoliciesEscapesPathAndBuildsRepeatedQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.URL.EscapedPath(); got != "/api/v1/policies/alice%2Fops" {
			t.Errorf("escaped path = %q", got)
		}
		if got := request.URL.Query()["groups[]"]; len(got) != 2 || got[0] != "admins" || got[1] != "users" {
			t.Errorf("groups query = %#v", got)
		}
		if got := request.URL.Query()["namespaces[]"]; len(got) != 1 || got[0] != "App::Docs" {
			t.Errorf("namespaces query = %#v", got)
		}
		_, _ = io.WriteString(response, `{"user":"alice/ops","policies":[],"matches":[]}`)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UserPolicies(context.Background(), "alice/ops", FilterGroups("admins", "users"), FilterNamespaces(testNamespace(t, "App", "Docs")))
	if err != nil {
		t.Fatal(err)
	}
	if result.User != "alice/ops" {
		t.Fatalf("user = %q", result.User)
	}
}

func TestCredentialsRequireSecureNonLoopbackTransport(t *testing.T) {
	token, err := NewAccessToken("secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = New("http://example.com", WithAccessToken(token))
	var config *ConfigurationError
	if !errors.As(err, &config) {
		t.Fatalf("got %T %v, want *ConfigurationError", err, err)
	}
}

func TestNilContextIsRejected(t *testing.T) {
	client, err := New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	err = client.Health(nil)
	var config *ConfigurationError
	if !errors.As(err, &config) {
		t.Fatalf("got %T %v, want *ConfigurationError", err, err)
	}
}

func TestAPIErrorPreservesCodeAndDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(response, `{"error":"invalid policy","code":"invalid_policy","details":{"line":3,"column":9}}`)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Health(context.Background())
	var apiError *APIError
	if !errors.As(err, &apiError) {
		t.Fatalf("got %T %v, want *APIError", err, err)
	}
	if apiError.Code != "invalid_policy" || apiError.Details == nil || *apiError.Details.Line != 3 {
		t.Fatalf("unexpected API error: %#v", apiError)
	}
}

func TestTextResponseRejectsInvalidUTF8(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte{0xff})
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Metrics(context.Background())
	var invalid *InvalidResponseError
	if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("got %T %v, want UTF-8 InvalidResponseError", err, err)
	}
}
