package treetop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

type requestSpec struct {
	method      string
	url         *url.URL
	body        io.Reader
	contentType string
	accept      string
	protected   bool
	uploadToken *UploadToken
}

func (c *Client) newRequest(ctx context.Context, spec requestSpec) (*http.Request, error) {
	if ctx == nil {
		return nil, &ConfigurationError{Message: "context must not be nil"}
	}
	request, err := http.NewRequestWithContext(ctx, spec.method, spec.url.String(), spec.body)
	if err != nil {
		return nil, fmt.Errorf("treetop: construct HTTP request: %w", err)
	}
	if spec.contentType != "" {
		request.Header.Set("Content-Type", spec.contentType)
	}
	if spec.accept != "" {
		request.Header.Set("Accept", spec.accept)
	}
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	if c.correlationID != "" {
		request.Header.Set("x-correlation-id", c.correlationID)
	}
	if spec.protected && c.accessToken != nil {
		request.Header.Set("Authorization", "Bearer "+c.accessToken.exposed())
	}
	if spec.uploadToken != nil {
		request.Header.Set("X-Upload-Token", spec.uploadToken.exposed())
	}
	return request, nil
}

func (c *Client) send(ctx context.Context, spec requestSpec) (*http.Response, error) {
	request, err := c.newRequest(ctx, spec)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("treetop: HTTP transport: %w", err)
	}
	return response, nil
}

func (c *Client) decodeJSON(response *http.Response, target any, uploadToken *UploadToken) error {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return c.apiError(response, uploadToken)
	}
	body, err := readBounded(response, c.maxResponseBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("treetop: decode response JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return &InvalidResponseError{Message: "response contains more than one JSON value"}
		}
		return fmt.Errorf("treetop: decode trailing response JSON: %w", err)
	}
	return nil
}

func (c *Client) decodeText(response *http.Response, uploadToken *UploadToken) (string, error) {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", c.apiError(response, uploadToken)
	}
	return c.readText(response)
}

func (c *Client) readText(response *http.Response) (string, error) {
	body, err := readBounded(response, c.maxResponseBytes)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(body) {
		return "", &InvalidResponseError{Message: "successful text response is not valid UTF-8"}
	}
	return string(body), nil
}

func (c *Client) apiError(response *http.Response, uploadToken *UploadToken) error {
	body, err := readBounded(response, defaultErrorBodyBytes)
	if err != nil {
		var tooLarge *ResponseTooLargeError
		if errors.As(err, &tooLarge) {
			return &APIError{StatusCode: response.StatusCode, Message: fmt.Sprintf("response error body exceeded %d bytes", defaultErrorBodyBytes)}
		}
		return err
	}
	secrets := make([][]byte, 0, 2)
	if c.accessToken != nil {
		secrets = append(secrets, c.accessToken.value)
	}
	if uploadToken != nil {
		secrets = append(secrets, uploadToken.value)
	}
	var envelope struct {
		Error   string        `json:"error"`
		Code    string        `json:"code"`
		Details *ErrorDetails `json:"details"`
	}
	message := strings.ToValidUTF8(string(body), "�")
	if json.Unmarshal(body, &envelope) == nil && envelope.Error != "" {
		message = envelope.Error
	}
	return &APIError{
		StatusCode: response.StatusCode,
		Code:       envelope.Code,
		Message:    redactSecrets(message, secrets...),
		Details:    envelope.Details,
	}
}

func readBounded(response *http.Response, limit int64) ([]byte, error) {
	defer response.Body.Close()
	if response.ContentLength > limit {
		return nil, &ResponseTooLargeError{Limit: limit}
	}
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	reader := io.LimitReader(response.Body, readLimit)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("treetop: read response body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, &ResponseTooLargeError{Limit: limit}
	}
	return body, nil
}

func encodeJSONBounded(value any, limit int64) ([]byte, error) {
	buffer := &limitedBuffer{limit: limit}
	if err := json.NewEncoder(buffer).Encode(value); err != nil {
		if errors.Is(err, errSizeLimit) {
			return nil, &RequestTooLargeError{Limit: limit}
		}
		return nil, fmt.Errorf("treetop: encode request JSON: %w", err)
	}
	return buffer.Bytes(), nil
}

var errSizeLimit = errors.New("size limit exceeded")

type limitedBuffer struct {
	bytes.Buffer
	limit int64
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	if int64(len(value)) > b.limit-int64(b.Len()) {
		return 0, errSizeLimit
	}
	return b.Buffer.Write(value)
}

func validateRawBody(size, limit int64) error {
	if size > limit {
		return &RequestTooLargeError{Limit: limit}
	}
	return nil
}
