package treetop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Health checks the legacy protected GET /api/v1/health endpoint.
func (c *Client) Health(ctx context.Context) error {
	response, err := c.send(ctx, requestSpec{method: http.MethodGet, url: c.endpoint("health"), protected: true})
	if err != nil {
		return err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return c.apiError(response, nil)
	}
	_, err = readBounded(response, min64(defaultErrorBodyBytes, c.maxResponseBytes))
	return err
}

// Live checks the canonical public GET /livez process probe.
func (c *Client) Live(ctx context.Context) error {
	response, err := c.send(ctx, requestSpec{method: http.MethodGet, url: c.rootEndpoint("livez"), accept: "text/plain"})
	if err != nil {
		return err
	}
	_, err = c.decodeText(response, nil)
	return err
}

// Ready checks the canonical public GET /readyz probe. HTTP 503 is a normal
// not-ready result; all other unexpected statuses are API errors.
func (c *Client) Ready(ctx context.Context) (bool, error) {
	response, err := c.send(ctx, requestSpec{method: http.MethodGet, url: c.rootEndpoint("readyz"), accept: "text/plain"})
	if err != nil {
		return false, err
	}
	if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusServiceUnavailable {
		status := response.StatusCode
		if _, err := c.readText(response); err != nil {
			return false, err
		}
		return status == http.StatusOK, nil
	}
	return false, c.apiError(response, nil)
}

// OpenAPI returns the validated raw JSON document from GET /openapi.json.
func (c *Client) OpenAPI(ctx context.Context) (json.RawMessage, error) {
	response, err := c.send(ctx, requestSpec{method: http.MethodGet, url: c.rootEndpoint("openapi.json"), accept: "application/json"})
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, c.apiError(response, nil)
	}
	body, err := readBounded(response, c.maxResponseBytes)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, &InvalidResponseError{Message: "OpenAPI response is not valid JSON"}
	}
	return json.RawMessage(body), nil
}

// Version returns server, core, Cedar, policy, and optional schema versions.
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	var result VersionInfo
	if err := c.getJSON(ctx, c.endpoint("version"), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Status returns current policy metadata and runtime configuration.
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	var result StatusResponse
	if err := c.getJSON(ctx, c.endpoint("status"), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Authorize evaluates a batch and returns brief decisions.
func (c *Client) Authorize(ctx context.Context, request *AuthorizeRequest) (*AuthorizeBriefResponse, error) {
	if err := c.validateAuthorization(request); err != nil {
		return nil, err
	}
	var result AuthorizeBriefResponse
	if err := c.postAuthorization(ctx, "brief", request, &result); err != nil {
		return nil, err
	}
	if err := validateAuthorizeResponse(&result, request); err != nil {
		return nil, err
	}
	return &result, nil
}

// AuthorizeDetailed evaluates a batch and includes full matching policies.
func (c *Client) AuthorizeDetailed(ctx context.Context, request *AuthorizeRequest) (*AuthorizeDetailedResponse, error) {
	if err := c.validateAuthorization(request); err != nil {
		return nil, err
	}
	var result AuthorizeDetailedResponse
	if err := c.postAuthorization(ctx, "full", request, &result); err != nil {
		return nil, err
	}
	if err := validateAuthorizeResponse(&result, request); err != nil {
		return nil, err
	}
	return &result, nil
}

// IsAllowed evaluates one request and returns true for Allow and false for
// Deny. An item-level evaluation failure is returned as *EvaluationError.
func (c *Client) IsAllowed(ctx context.Context, request Request) (bool, error) {
	batch, err := SingleAuthorizeRequest(request)
	if err != nil {
		return false, err
	}
	response, err := c.Authorize(ctx, batch)
	if err != nil {
		return false, err
	}
	if len(response.Results) != 1 {
		return false, &InvalidResponseError{Message: "single authorize response does not contain exactly one item"}
	}
	item := response.Results[0]
	if item.Status == BatchStatusFailed {
		return false, &EvaluationError{Message: item.Error}
	}
	return item.Result.Decision == DecisionAllow, nil
}

// Policies downloads structured policy metadata and content.
func (c *Client) Policies(ctx context.Context) (*PoliciesDownload, error) {
	var result PoliciesDownload
	if err := c.getJSON(ctx, c.endpoint("policies"), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PoliciesText downloads raw Cedar policy text.
func (c *Client) PoliciesText(ctx context.Context) (string, error) {
	endpoint := c.endpoint("policies")
	endpoint.RawQuery = "format=raw"
	return c.getText(ctx, endpoint, true)
}

// Schema downloads structured schema metadata and content.
func (c *Client) Schema(ctx context.Context) (*SchemaDownload, error) {
	var result SchemaDownload
	if err := c.getJSON(ctx, c.endpoint("schema"), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SchemaText downloads raw Cedar schema JSON text.
func (c *Client) SchemaText(ctx context.Context) (string, error) {
	endpoint := c.endpoint("schema")
	endpoint.RawQuery = "format=raw"
	return c.getText(ctx, endpoint, true)
}

// UserPoliciesOption configures a user-policy query.
type UserPoliciesOption func(*userPoliciesQuery) error

type userPoliciesQuery struct {
	groups     []string
	namespaces []Namespace
}

// FilterGroups includes group memberships in a user-policy query.
func FilterGroups(groups ...string) UserPoliciesOption {
	return func(query *userPoliciesQuery) error {
		for _, group := range groups {
			if err := validateEntityID("user policies group", group); err != nil {
				return err
			}
		}
		query.groups = append(query.groups, groups...)
		return nil
	}
}

// FilterNamespaces restricts a user-policy query to qualified Cedar namespaces.
func FilterNamespaces(namespaces ...Namespace) UserPoliciesOption {
	return func(query *userPoliciesQuery) error {
		for _, namespace := range namespaces {
			if namespace.IsEmpty() {
				return &ValidationError{Field: "user policies namespace", Rule: "must not be the global namespace"}
			}
			if err := namespace.validate("user policies namespace"); err != nil {
				return err
			}
		}
		query.namespaces = append(query.namespaces, namespaces...)
		return nil
	}
}

// UserPolicies lists policies applying to user.
func (c *Client) UserPolicies(ctx context.Context, user string, options ...UserPoliciesOption) (*UserPolicies, error) {
	endpoint, err := c.buildUserPoliciesURL(user, false, options)
	if err != nil {
		return nil, err
	}
	var result UserPolicies
	if err := c.getJSON(ctx, endpoint, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UserPoliciesText lists policies applying to user as raw Cedar text.
func (c *Client) UserPoliciesText(ctx context.Context, user string, options ...UserPoliciesOption) (string, error) {
	endpoint, err := c.buildUserPoliciesURL(user, true, options)
	if err != nil {
		return "", err
	}
	return c.getText(ctx, endpoint, true)
}

// Metrics returns Prometheus/OpenMetrics text from the protected /metrics endpoint.
func (c *Client) Metrics(ctx context.Context) (string, error) {
	return c.getText(ctx, c.rootEndpoint("metrics"), true)
}

func (c *Client) validateAuthorization(request *AuthorizeRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	return request.validateLimits(c.requestLimits)
}

func (c *Client) postAuthorization(ctx context.Context, detail string, request *AuthorizeRequest, target any) error {
	body, err := encodeJSONBounded(request, c.maxRequestBytes)
	if err != nil {
		return err
	}
	endpoint := c.endpoint("authorize")
	query := endpoint.Query()
	query.Set("detail", detail)
	endpoint.RawQuery = query.Encode()
	response, err := c.send(ctx, requestSpec{
		method: http.MethodPost, url: endpoint, body: bytes.NewReader(body),
		contentType: "application/json", accept: "application/json", protected: true,
	})
	if err != nil {
		return err
	}
	return c.decodeJSON(response, target, nil)
}

func (c *Client) getJSON(ctx context.Context, endpoint *url.URL, target any) error {
	response, err := c.send(ctx, requestSpec{method: http.MethodGet, url: endpoint, accept: "application/json", protected: true})
	if err != nil {
		return err
	}
	return c.decodeJSON(response, target, nil)
}

func (c *Client) getText(ctx context.Context, endpoint *url.URL, protected bool) (string, error) {
	response, err := c.send(ctx, requestSpec{method: http.MethodGet, url: endpoint, accept: "text/plain", protected: protected})
	if err != nil {
		return "", err
	}
	return c.decodeText(response, nil)
}

func (c *Client) buildUserPoliciesURL(user string, raw bool, options []UserPoliciesOption) (*url.URL, error) {
	endpoint, err := c.userPoliciesEndpoint(user)
	if err != nil {
		return nil, err
	}
	var queryConfig userPoliciesQuery
	for i, option := range options {
		if option == nil {
			return nil, &ConfigurationError{Message: fmt.Sprintf("user policy option %d is nil", i)}
		}
		if err := option(&queryConfig); err != nil {
			return nil, err
		}
	}
	query := make(url.Values)
	for _, namespace := range queryConfig.namespaces {
		query.Add("namespaces[]", namespace.String())
	}
	for _, group := range queryConfig.groups {
		query.Add("groups[]", group)
	}
	if raw {
		query.Set("format", "raw")
	}
	endpoint.RawQuery = query.Encode()
	return endpoint, nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
