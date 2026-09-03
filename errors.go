package treetop

import (
	"fmt"
	"net/http"
)

// ValidationError reports a value that cannot be represented safely by
// Treetop or Cedar.
type ValidationError struct {
	Field string
	Rule  string
	Value string
}

func (e *ValidationError) Error() string {
	if e.Value == "" {
		return fmt.Sprintf("treetop: invalid %s: %s", e.Field, e.Rule)
	}
	return fmt.Sprintf("treetop: invalid %s %q: %s", e.Field, e.Value, e.Rule)
}

// ConfigurationError reports invalid client configuration.
type ConfigurationError struct {
	Message string
}

func (e *ConfigurationError) Error() string {
	return "treetop: client configuration: " + e.Message
}

// APIError is returned when the server responds with a non-2xx status.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	Details    *ErrorDetails
}

func (e *APIError) Error() string {
	status := fmt.Sprint(e.StatusCode)
	if text := http.StatusText(e.StatusCode); text != "" {
		status += " " + text
	}
	if e.Code != "" {
		return fmt.Sprintf("treetop: API error (HTTP %s, %s): %s", status, e.Code, e.Message)
	}
	return fmt.Sprintf("treetop: API error (HTTP %s): %s", status, e.Message)
}

// ErrorDetails identifies a source location associated with an API error.
type ErrorDetails struct {
	Line   *uint64 `json:"line,omitempty"`
	Column *uint64 `json:"column,omitempty"`
}

// RequestTooLargeError reports a locally rejected outbound body.
type RequestTooLargeError struct {
	Limit int64
}

func (e *RequestTooLargeError) Error() string {
	return fmt.Sprintf("treetop: request body exceeds the configured limit of %d bytes", e.Limit)
}

// ResponseTooLargeError reports a successful response body that exceeded its
// configured bound.
type ResponseTooLargeError struct {
	Limit int64
}

func (e *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("treetop: response body exceeds the configured limit of %d bytes", e.Limit)
}

// InvalidResponseError reports a structurally inconsistent successful server
// response.
type InvalidResponseError struct {
	Message string
}

func (e *InvalidResponseError) Error() string {
	return "treetop: invalid API response: " + e.Message
}

// EvaluationError reports a failed item in an otherwise successful
// authorization batch.
type EvaluationError struct {
	Message string
}

func (e *EvaluationError) Error() string {
	return "treetop: authorization evaluation failed: " + e.Message
}
