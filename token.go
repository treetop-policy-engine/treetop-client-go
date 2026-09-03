package treetop

import (
	"fmt"
	"strings"
)

const redacted = "[REDACTED]"

// AccessToken is an opaque Bearer token for protected Treetop endpoints. Its
// formatting methods never reveal the token. Go cannot guarantee that copies
// made by the runtime or HTTP stack are zeroized.
type AccessToken struct {
	value []byte
}

// NewAccessToken validates the HTTP Bearer b64token grammar.
func NewAccessToken(value string) (AccessToken, error) {
	if !validBearerToken(value) {
		return AccessToken{}, &ValidationError{Field: "access token", Rule: "must be non-empty and contain only HTTP Bearer token characters"}
	}
	return AccessToken{value: []byte(value)}, nil
}

// String returns a redacted representation.
func (AccessToken) String() string { return "AccessToken(" + redacted + ")" }

// GoString returns a redacted representation for %#v formatting.
func (AccessToken) GoString() string { return "AccessToken(" + redacted + ")" }

func (t AccessToken) clone() AccessToken {
	return AccessToken{value: append([]byte(nil), t.value...)}
}

func (t AccessToken) exposed() string { return string(t.value) }

// Destroy overwrites the token's owned byte slice. It does not erase copies
// previously made by the Go runtime, an HTTP transport, or another token value.
func (t *AccessToken) Destroy() {
	if t == nil {
		return
	}
	clear(t.value)
	t.value = nil
}

func (t AccessToken) validate() error {
	if !validBearerToken(t.exposed()) {
		return &ValidationError{Field: "access token", Rule: "must be non-empty and contain only HTTP Bearer token characters"}
	}
	return nil
}

// UploadToken authenticates policy, schema, and bundle uploads. Its formatting
// methods never reveal the token.
type UploadToken struct {
	value []byte
}

// NewUploadToken validates that value is a non-empty HTTP header field value.
func NewUploadToken(value string) (UploadToken, error) {
	if value == "" || !validHeaderValue(value) {
		return UploadToken{}, &ValidationError{Field: "upload token", Rule: "must be non-empty and contain only valid HTTP header characters"}
	}
	return UploadToken{value: []byte(value)}, nil
}

// String returns a redacted representation.
func (UploadToken) String() string { return "UploadToken(" + redacted + ")" }

// GoString returns a redacted representation for %#v formatting.
func (UploadToken) GoString() string { return "UploadToken(" + redacted + ")" }

func (t UploadToken) clone() UploadToken {
	return UploadToken{value: append([]byte(nil), t.value...)}
}

func (t UploadToken) exposed() string { return string(t.value) }

// Destroy overwrites the token's owned byte slice. It does not erase copies
// previously made by the Go runtime, an HTTP transport, or another token value.
func (t *UploadToken) Destroy() {
	if t == nil {
		return
	}
	clear(t.value)
	t.value = nil
}

func (t UploadToken) validate() error {
	if t.exposed() == "" || !validHeaderValue(t.exposed()) {
		return &ValidationError{Field: "upload token", Rule: "must be non-empty and contain only valid HTTP header characters"}
	}
	return nil
}

func validBearerToken(value string) bool {
	body := 0
	padding := false
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b == '=' {
			padding = true
			continue
		}
		if padding || !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || strings.ContainsRune("-._~+/", rune(b))) {
			return false
		}
		body++
	}
	return body > 0
}

func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b < 0x20 && b != '\t') || b == 0x7f {
			return false
		}
	}
	return true
}

func redactSecrets(message string, secrets ...[]byte) string {
	for _, secret := range secrets {
		if len(secret) != 0 {
			message = strings.ReplaceAll(message, string(secret), redacted)
		}
	}
	return message
}

var _ fmt.Stringer = AccessToken{}
var _ fmt.GoStringer = AccessToken{}
var _ fmt.Stringer = UploadToken{}
var _ fmt.GoStringer = UploadToken{}
