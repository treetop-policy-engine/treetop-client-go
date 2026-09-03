package treetop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	defaultConnectTimeout  = 5 * time.Second
	defaultRequestTimeout  = 30 * time.Second
	defaultIdleConnTimeout = 90 * time.Second
	defaultMaxBodyBytes    = int64(16 << 20)
	defaultErrorBodyBytes  = int64(64 << 10)
	defaultUserAgent       = "treetop-client-go"
)

type clientConfig struct {
	httpClient            *http.Client
	connectTimeout        time.Duration
	requestTimeout        time.Duration
	idleConnTimeout       time.Duration
	maxIdleConnsPerHost   int
	maxRequestBytes       int64
	maxResponseBytes      int64
	requestLimits         RequestLimits
	accessToken           *AccessToken
	allowInsecureAccess   bool
	correlationID         string
	rootCAPEM             [][]byte
	skipTLSVerify         bool
	userAgent             string
	connectTimeoutChanged bool
	idleTimeoutChanged    bool
	maxIdleChanged        bool
	requestTimeoutChanged bool
	tlsOptionsChanged     bool
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		connectTimeout:      defaultConnectTimeout,
		requestTimeout:      defaultRequestTimeout,
		idleConnTimeout:     defaultIdleConnTimeout,
		maxIdleConnsPerHost: http.DefaultMaxIdleConnsPerHost,
		maxRequestBytes:     defaultMaxBodyBytes,
		maxResponseBytes:    defaultMaxBodyBytes,
		requestLimits:       DefaultRequestLimits(),
		userAgent:           defaultUserAgent,
	}
}

// Option configures a Client.
type Option func(*clientConfig) error

// WithHTTPClient uses client's transport and timeout configuration. The value
// is shallow-copied, its standard Transport is cloned when possible, and its
// redirect policy is replaced with redirect denial to protect credentials.
func WithHTTPClient(client *http.Client) Option {
	return func(config *clientConfig) error {
		if client == nil {
			return &ConfigurationError{Message: "HTTP client must not be nil"}
		}
		config.httpClient = client
		return nil
	}
}

// WithConnectTimeout sets the default transport's TCP connection timeout.
func WithConnectTimeout(timeout time.Duration) Option {
	return func(config *clientConfig) error {
		if timeout <= 0 {
			return &ConfigurationError{Message: "connect timeout must be greater than zero"}
		}
		config.connectTimeout = timeout
		config.connectTimeoutChanged = true
		return nil
	}
}

// WithRequestTimeout sets the whole-request timeout. Per-call context
// deadlines can impose a shorter timeout.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(config *clientConfig) error {
		if timeout <= 0 {
			return &ConfigurationError{Message: "request timeout must be greater than zero"}
		}
		config.requestTimeout = timeout
		config.requestTimeoutChanged = true
		return nil
	}
}

// WithIdleConnTimeout sets how long pooled idle connections are retained.
func WithIdleConnTimeout(timeout time.Duration) Option {
	return func(config *clientConfig) error {
		if timeout < 0 {
			return &ConfigurationError{Message: "idle connection timeout must not be negative"}
		}
		config.idleConnTimeout = timeout
		config.idleTimeoutChanged = true
		return nil
	}
}

// WithMaxIdleConnectionsPerHost sets the per-host idle connection pool size.
func WithMaxIdleConnectionsPerHost(maximum int) Option {
	return func(config *clientConfig) error {
		if maximum <= 0 {
			return &ConfigurationError{Message: "maximum idle connections per host must be greater than zero"}
		}
		config.maxIdleConnsPerHost = maximum
		config.maxIdleChanged = true
		return nil
	}
}

// WithMaxRequestBytes bounds every serialized request and upload body.
func WithMaxRequestBytes(maximum int64) Option {
	return func(config *clientConfig) error {
		if maximum <= 0 {
			return &ConfigurationError{Message: "maximum request size must be greater than zero"}
		}
		config.maxRequestBytes = maximum
		return nil
	}
}

// WithMaxResponseBytes bounds every successful response body.
func WithMaxResponseBytes(maximum int64) Option {
	return func(config *clientConfig) error {
		if maximum <= 0 {
			return &ConfigurationError{Message: "maximum response size must be greater than zero"}
		}
		config.maxResponseBytes = maximum
		return nil
	}
}

// WithRequestLimits sets locally enforced batch and per-request context limits.
func WithRequestLimits(limits RequestLimits) Option {
	return func(config *clientConfig) error {
		if err := limits.validate(); err != nil {
			return err
		}
		config.requestLimits = limits
		return nil
	}
}

// WithAccessToken adds a Bearer token to /api/v1/** and /metrics requests. It
// is intentionally omitted from /livez, /readyz, and /openapi.json.
func WithAccessToken(token AccessToken) Option {
	return func(config *clientConfig) error {
		if err := token.validate(); err != nil {
			return err
		}
		copy := token.clone()
		config.accessToken = &copy
		return nil
	}
}

// DangerouslyAllowInsecureAccessToken permits a Bearer token to be sent over
// non-loopback plaintext HTTP. Prefer HTTPS.
func DangerouslyAllowInsecureAccessToken() Option {
	return func(config *clientConfig) error {
		config.allowInsecureAccess = true
		return nil
	}
}

// WithCorrelationID sets a default x-correlation-id header. Use
// Client.WithCorrelationID for an inexpensive per-operation copy.
func WithCorrelationID(id string) Option {
	return func(config *clientConfig) error {
		if err := validateCorrelationID(id); err != nil {
			return err
		}
		config.correlationID = id
		return nil
	}
}

// WithRootCAPEM adds one or more PEM-encoded root CA certificates to the
// existing trust pool, or the system trust pool when none is configured.
func WithRootCAPEM(pem []byte) Option {
	return func(config *clientConfig) error {
		if len(pem) == 0 {
			return &ConfigurationError{Message: "root CA PEM must not be empty"}
		}
		config.rootCAPEM = append(config.rootCAPEM, append([]byte(nil), pem...))
		config.tlsOptionsChanged = true
		return nil
	}
}

// DangerouslySkipTLSVerification disables certificate and hostname checks.
// It is intended only for controlled development environments.
func DangerouslySkipTLSVerification() Option {
	return func(config *clientConfig) error {
		config.skipTLSVerify = true
		config.tlsOptionsChanged = true
		return nil
	}
}

// WithUserAgent replaces the default treetop-client-go User-Agent value.
func WithUserAgent(value string) Option {
	return func(config *clientConfig) error {
		if value == "" || !validHeaderValue(value) {
			return &ConfigurationError{Message: "user agent must be a non-empty valid HTTP header value"}
		}
		config.userAgent = value
		return nil
	}
}

func validateCorrelationID(id string) error {
	if id == "" || !validHeaderValue(id) {
		return &ConfigurationError{Message: "correlation ID must be a non-empty valid HTTP header value"}
	}
	return nil
}

func buildHTTPClient(config clientConfig) (*http.Client, error) {
	var client http.Client
	customClient := config.httpClient != nil
	if config.httpClient != nil {
		client = *config.httpClient
	} else {
		client.Timeout = config.requestTimeout
	}

	transport, standard := client.Transport.(*http.Transport)
	if client.Transport == nil {
		if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = defaultTransport.Clone()
		} else {
			transport = &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
		}
		standard = true
	} else if standard {
		transport = transport.Clone()
	}
	transportOptionsChanged := config.connectTimeoutChanged || config.idleTimeoutChanged || config.maxIdleChanged || config.tlsOptionsChanged
	if !standard && transportOptionsChanged {
		return nil, &ConfigurationError{Message: "transport options require an *http.Transport"}
	}
	if standard {
		if !customClient || config.connectTimeoutChanged {
			dialer := &net.Dialer{Timeout: config.connectTimeout, KeepAlive: 30 * time.Second}
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			}
		}
		if !customClient || config.idleTimeoutChanged {
			transport.IdleConnTimeout = config.idleConnTimeout
		}
		if !customClient || config.maxIdleChanged {
			transport.MaxIdleConnsPerHost = config.maxIdleConnsPerHost
		}
		if !customClient {
			transport.ForceAttemptHTTP2 = true
		}
		if len(config.rootCAPEM) != 0 || config.skipTLSVerify {
			tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
			if transport.TLSClientConfig != nil {
				tlsConfig = transport.TLSClientConfig.Clone()
				if tlsConfig.MinVersion == 0 {
					tlsConfig.MinVersion = tls.VersionTLS12
				}
			}
			if len(config.rootCAPEM) != 0 {
				var roots *x509.CertPool
				if tlsConfig.RootCAs != nil {
					roots = tlsConfig.RootCAs.Clone()
				} else {
					var err error
					roots, err = x509.SystemCertPool()
					if err != nil || roots == nil {
						roots = x509.NewCertPool()
					}
				}
				for _, pem := range config.rootCAPEM {
					if !roots.AppendCertsFromPEM(pem) {
						return nil, &ConfigurationError{Message: "root CA PEM contains no valid certificates"}
					}
				}
				tlsConfig.RootCAs = roots
			}
			// This assignment is intentionally confined to the danger-prefixed option.
			tlsConfig.InsecureSkipVerify = config.skipTLSVerify //nolint:gosec
			transport.TLSClientConfig = tlsConfig
		}
		client.Transport = transport
	}
	if !customClient || config.requestTimeoutChanged {
		client.Timeout = config.requestTimeout
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client, nil
}

func applyOptions(options []Option) (clientConfig, error) {
	config := defaultClientConfig()
	for i, option := range options {
		if option == nil {
			return clientConfig{}, &ConfigurationError{Message: fmt.Sprintf("option %d is nil", i)}
		}
		if err := option(&config); err != nil {
			return clientConfig{}, err
		}
	}
	if err := config.requestLimits.validate(); err != nil {
		return clientConfig{}, err
	}
	return config, nil
}
