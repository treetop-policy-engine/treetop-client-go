package treetop

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploaderSendsBothCredentialsAndBundle(t *testing.T) {
	bundle := []byte("gzip bytes")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/bundle" || request.Header.Get("Content-Type") != "application/gzip" {
			t.Errorf("unexpected request: %s %s", request.URL.Path, request.Header.Get("Content-Type"))
		}
		if request.Header.Get("Authorization") != "Bearer access-secret" || request.Header.Get("X-Upload-Token") != "upload-secret" {
			t.Error("upload credentials are missing")
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != string(bundle) {
			t.Errorf("body = %q", body)
		}
		_, _ = io.WriteString(response, `{}`)
	}))
	defer server.Close()

	access, _ := NewAccessToken("access-secret")
	upload, _ := NewUploadToken("upload-secret")
	client, err := New(server.URL, WithAccessToken(access))
	if err != nil {
		t.Fatal(err)
	}
	uploader, err := client.Uploader(upload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uploader.UploadBundle(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
}

func TestUploaderRedactsReflectedCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(response, `{"error":"rejected access-secret and upload-secret"}`)
	}))
	defer server.Close()
	access, _ := NewAccessToken("access-secret")
	upload, _ := NewUploadToken("upload-secret")
	client, err := New(server.URL, WithAccessToken(access))
	if err != nil {
		t.Fatal(err)
	}
	uploader, err := client.Uploader(upload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = uploader.UploadPolicies(context.Background(), "permit(principal, action, resource);")
	var apiError *APIError
	if !errors.As(err, &apiError) {
		t.Fatalf("got %T %v, want *APIError", err, err)
	}
	if strings.Contains(err.Error(), "access-secret") || strings.Contains(err.Error(), "upload-secret") {
		t.Fatalf("credential leaked in error: %v", err)
	}
	if strings.Count(apiError.Message, redacted) != 2 {
		t.Fatalf("message = %q", apiError.Message)
	}
}

func TestUploaderRejectsInsecureRemoteHTTP(t *testing.T) {
	client, err := New("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	token, _ := NewUploadToken("secret")
	_, err = client.Uploader(token)
	var config *ConfigurationError
	if !errors.As(err, &config) {
		t.Fatalf("got %T %v, want *ConfigurationError", err, err)
	}
	if _, err := client.Uploader(token, DangerouslyAllowInsecureUploads()); err != nil {
		t.Fatalf("explicit insecure opt-in failed: %v", err)
	}
}

func TestUploadSchemaDocumentRequiresJSONObject(t *testing.T) {
	client, err := New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	token, _ := NewUploadToken("secret")
	uploader, err := client.Uploader(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uploader.UploadSchemaDocument(context.Background(), []byte(`[]`)); err == nil {
		t.Fatal("expected array schema document to be rejected")
	}
}
