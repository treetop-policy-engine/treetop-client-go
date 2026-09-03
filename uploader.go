package treetop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Uploader is a capability-scoped client for policy, schema, and bundle
// replacement. It is safe for concurrent use.
type Uploader struct {
	client *Client
	token  UploadToken
}

type uploaderConfig struct {
	allowInsecure bool
}

// UploaderOption configures creation of an Uploader.
type UploaderOption func(*uploaderConfig) error

// DangerouslyAllowInsecureUploads permits the upload token to be sent over
// non-loopback plaintext HTTP. Prefer HTTPS.
func DangerouslyAllowInsecureUploads() UploaderOption {
	return func(config *uploaderConfig) error {
		config.allowInsecure = true
		return nil
	}
}

// Uploader creates an upload-capable view of this client. Upload methods are
// deliberately absent from Client itself.
func (c *Client) Uploader(token UploadToken, options ...UploaderOption) (*Uploader, error) {
	if c == nil {
		return nil, &ConfigurationError{Message: "client must not be nil"}
	}
	if err := token.validate(); err != nil {
		return nil, err
	}
	var config uploaderConfig
	for i, option := range options {
		if option == nil {
			return nil, &ConfigurationError{Message: fmt.Sprintf("uploader option %d is nil", i)}
		}
		if err := option(&config); err != nil {
			return nil, err
		}
	}
	if !secureCredentialTransport(c.baseURL, config.allowInsecure) {
		return nil, &ConfigurationError{Message: "refusing to send an upload token over plaintext HTTP; use HTTPS or DangerouslyAllowInsecureUploads"}
	}
	return &Uploader{client: c, token: token.clone()}, nil
}

// WithCorrelationID returns an uploader sharing its HTTP connection pool with
// a different correlation ID.
func (u *Uploader) WithCorrelationID(id string) (*Uploader, error) {
	if u == nil {
		return nil, &ConfigurationError{Message: "uploader must not be nil"}
	}
	client, err := u.client.WithCorrelationID(id)
	if err != nil {
		return nil, err
	}
	return &Uploader{client: client, token: u.token.clone()}, nil
}

// String returns a credential-free description of the uploader.
func (u *Uploader) String() string {
	if u == nil {
		return "Uploader(<nil>)"
	}
	return fmt.Sprintf("Uploader(client=%s, upload_token=true)", u.client)
}

// UploadPolicies replaces policies using raw Cedar DSL and text/plain.
func (u *Uploader) UploadPolicies(ctx context.Context, cedar string) (*PoliciesMetadata, error) {
	if err := validateRawBody(int64(len(cedar)), u.client.maxRequestBytes); err != nil {
		return nil, err
	}
	return u.post(ctx, "policies", "text/plain", []byte(cedar))
}

// UploadPoliciesJSON replaces policies using the JSON wrapper
// {"policies":"<cedar>"}.
func (u *Uploader) UploadPoliciesJSON(ctx context.Context, cedar string) (*PoliciesMetadata, error) {
	body, err := encodeJSONBounded(struct {
		Policies string `json:"policies"`
	}{Policies: cedar}, u.client.maxRequestBytes)
	if err != nil {
		return nil, err
	}
	return u.postEncoded(ctx, "policies", "application/json", body)
}

// UploadSchema replaces the Cedar schema using text/plain.
func (u *Uploader) UploadSchema(ctx context.Context, schema string) (*PoliciesMetadata, error) {
	if err := validateRawBody(int64(len(schema)), u.client.maxRequestBytes); err != nil {
		return nil, err
	}
	return u.post(ctx, "schema", "text/plain", []byte(schema))
}

// UploadSchemaJSON replaces the Cedar schema using the JSON wrapper
// {"schema":"<schema-json>"}.
func (u *Uploader) UploadSchemaJSON(ctx context.Context, schema string) (*PoliciesMetadata, error) {
	body, err := encodeJSONBounded(struct {
		Schema string `json:"schema"`
	}{Schema: schema}, u.client.maxRequestBytes)
	if err != nil {
		return nil, err
	}
	return u.postEncoded(ctx, "schema", "application/json", body)
}

// UploadSchemaDocument replaces the Cedar schema using an unwrapped JSON
// object, a format supported by current Treetop REST servers.
func (u *Uploader) UploadSchemaDocument(ctx context.Context, schema json.RawMessage) (*PoliciesMetadata, error) {
	if err := validateRawBody(int64(len(schema)), u.client.maxRequestBytes); err != nil {
		return nil, err
	}
	if !json.Valid(schema) {
		return nil, &ValidationError{Field: "schema document", Rule: "must be valid JSON"}
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(schema, &object); err != nil || object == nil {
		return nil, &ValidationError{Field: "schema document", Rule: "must be a JSON object"}
	}
	return u.post(ctx, "schema", "application/json", schema)
}

// UploadBundle verifies and atomically applies a gzip-compressed Treetop
// bundle on the server.
func (u *Uploader) UploadBundle(ctx context.Context, bundle []byte) (*PoliciesMetadata, error) {
	return u.post(ctx, "bundle", "application/gzip", bundle)
}

func (u *Uploader) post(ctx context.Context, path, contentType string, body []byte) (*PoliciesMetadata, error) {
	if err := validateRawBody(int64(len(body)), u.client.maxRequestBytes); err != nil {
		return nil, err
	}
	return u.postEncoded(ctx, path, contentType, body)
}

func (u *Uploader) postEncoded(ctx context.Context, path, contentType string, body []byte) (*PoliciesMetadata, error) {
	response, err := u.client.send(ctx, requestSpec{
		method: http.MethodPost, url: u.client.endpoint(path), body: bytes.NewReader(body),
		contentType: contentType, accept: "application/json", protected: true, uploadToken: &u.token,
	})
	if err != nil {
		return nil, err
	}
	var result PoliciesMetadata
	if err := u.client.decodeJSON(response, &result, &u.token); err != nil {
		return nil, err
	}
	return &result, nil
}

var _ fmt.Stringer = (*Uploader)(nil)
