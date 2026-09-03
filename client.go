package treetop

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Client is a concurrency-safe Treetop REST client. Reuse it across requests
// to benefit from HTTP connection pooling.
type Client struct {
	http             *http.Client
	baseURL          *url.URL
	maxRequestBytes  int64
	maxResponseBytes int64
	requestLimits    RequestLimits
	accessToken      *AccessToken
	correlationID    string
	userAgent        string
}

// New constructs a Treetop client for baseURL. baseURL may contain a path
// prefix, but must not contain credentials, a query, or a fragment.
func New(baseURL string, options ...Option) (*Client, error) {
	base, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	config, err := applyOptions(options)
	if err != nil {
		return nil, err
	}
	if config.accessToken != nil && !secureCredentialTransport(base, config.allowInsecureAccess) {
		return nil, &ConfigurationError{Message: "refusing to send an access token over plaintext HTTP; use HTTPS or DangerouslyAllowInsecureAccessToken"}
	}
	httpClient, err := buildHTTPClient(config)
	if err != nil {
		return nil, err
	}
	return &Client{
		http: httpClient, baseURL: base,
		maxRequestBytes: config.maxRequestBytes, maxResponseBytes: config.maxResponseBytes,
		requestLimits: config.requestLimits, accessToken: config.accessToken,
		correlationID: config.correlationID, userAgent: config.userAgent,
	}, nil
}

// WithCorrelationID returns an inexpensive client copy sharing the same HTTP
// transport and connection pool with a different default correlation ID.
func (c *Client) WithCorrelationID(id string) (*Client, error) {
	if c == nil {
		return nil, &ConfigurationError{Message: "client must not be nil"}
	}
	if err := validateCorrelationID(id); err != nil {
		return nil, err
	}
	copy := *c
	copy.correlationID = id
	return &copy, nil
}

// WithoutCorrelationID returns an inexpensive client copy with no default
// correlation header.
func (c *Client) WithoutCorrelationID() *Client {
	if c == nil {
		return nil
	}
	copy := *c
	copy.correlationID = ""
	return &copy
}

// CloseIdleConnections closes pooled idle connections. Active calls are not
// interrupted, and the client remains usable.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

// String returns a credential-free description of the client.
func (c *Client) String() string {
	if c == nil {
		return "Client(<nil>)"
	}
	return fmt.Sprintf("Client(base_url=%s, access_token=%t, correlation_id=%q)", strings.TrimSuffix(c.baseURL.String(), "/"), c.accessToken != nil, c.correlationID)
}

func (c *Client) endpoint(path string) *url.URL {
	return c.rootEndpoint("api/v1/" + strings.TrimPrefix(path, "/"))
}

func (c *Client) rootEndpoint(path string) *url.URL {
	result := *c.baseURL
	result.Path = strings.TrimSuffix(c.baseURL.Path, "/") + "/" + strings.TrimPrefix(path, "/")
	result.RawPath = ""
	result.RawQuery = ""
	result.Fragment = ""
	return &result
}

func (c *Client) userPoliciesEndpoint(user string) (*url.URL, error) {
	if err := validateEntityID("user policies user", user); err != nil {
		return nil, err
	}
	if user == "" || user == "." || user == ".." {
		return nil, &ValidationError{Field: "user policies user", Value: user, Rule: "must be a non-empty endpoint path segment"}
	}
	result := c.endpoint("policies/")
	basePath := strings.TrimSuffix(result.Path, "/")
	result.Path = basePath + "/" + user
	result.RawPath = escapePath(basePath) + "/" + url.PathEscape(user)
	return result, nil
}

func parseBaseURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, &ConfigurationError{Message: "invalid base URL: " + err.Error()}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, &ConfigurationError{Message: "base URL scheme must be http or https"}
	}
	if parsed.Host == "" || parsed.Opaque != "" {
		return nil, &ConfigurationError{Message: "base URL must include a host"}
	}
	if parsed.User != nil {
		return nil, &ConfigurationError{Message: "base URL must not contain credentials"}
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, &ConfigurationError{Message: "base URL must not contain a query string or fragment"}
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/"
	parsed.RawPath = ""
	return parsed, nil
}

func secureCredentialTransport(base *url.URL, allowInsecure bool) bool {
	if base.Scheme == "https" || allowInsecure {
		return true
	}
	host := base.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func escapePath(path string) string {
	segments := strings.Split(path, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	return strings.Join(segments, "/")
}

var _ fmt.Stringer = (*Client)(nil)
