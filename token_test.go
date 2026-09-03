package treetop

import (
	"fmt"
	"strings"
	"testing"
)

func TestTokensValidateAndRedactFormatting(t *testing.T) {
	access, err := NewAccessToken("access-secret==")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := NewUploadToken("upload secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{
		fmt.Sprint(access), fmt.Sprintf("%#v", access),
		fmt.Sprint(upload), fmt.Sprintf("%#v", upload),
	} {
		if strings.Contains(formatted, "secret") || !strings.Contains(formatted, redacted) {
			t.Fatalf("unsafe token formatting: %q", formatted)
		}
	}
}

func TestAccessTokenBearerGrammar(t *testing.T) {
	valid := []string{"abc", "abc-._~+/", "abc=="}
	for _, value := range valid {
		if _, err := NewAccessToken(value); err != nil {
			t.Errorf("%q should be valid: %v", value, err)
		}
	}
	invalid := []string{"", "=", "abc=def", "has space", "has,comma", "bad\nheader"}
	for _, value := range invalid {
		if _, err := NewAccessToken(value); err == nil {
			t.Errorf("%q should be invalid", value)
		}
	}
}

func TestDestroyOverwritesOwnedBytes(t *testing.T) {
	token, err := NewUploadToken("secret")
	if err != nil {
		t.Fatal(err)
	}
	owned := token.value
	token.Destroy()
	for _, value := range owned {
		if value != 0 {
			t.Fatal("Destroy did not overwrite the owned byte slice")
		}
	}
}
