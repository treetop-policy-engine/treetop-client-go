package treetop

import (
	"net"
	"strings"
	"unicode"
)

func validateCedarIdentifier(field, value string) error {
	if isReservedCedarIdentifier(value) {
		return &ValidationError{Field: field, Value: value, Rule: "uses a reserved Cedar identifier"}
	}
	if value == "" || !asciiLetterOrUnderscore(value[0]) {
		return &ValidationError{Field: field, Value: value, Rule: "must be an ASCII Cedar identifier"}
	}
	for i := 1; i < len(value); i++ {
		if !asciiLetterDigitOrUnderscore(value[i]) {
			return &ValidationError{Field: field, Value: value, Rule: "must be an ASCII Cedar identifier"}
		}
	}
	return nil
}

func isReservedCedarIdentifier(value string) bool {
	switch value {
	case "true", "false", "if", "then", "else", "in", "like", "has", "is", "__cedar":
		return true
	default:
		return false
	}
}

func validateCedarPath(field, value string) error {
	for {
		separator := strings.Index(value, "::")
		segment := value
		if separator >= 0 {
			segment = value[:separator]
		}
		if err := validateCedarIdentifier(field, segment); err != nil {
			return err
		}
		if separator < 0 {
			return nil
		}
		value = value[separator+2:]
	}
}

func validateNamespace(field string, namespace []string) error {
	for _, segment := range namespace {
		if err := validateCedarIdentifier(field, segment); err != nil {
			return err
		}
	}
	return nil
}

func validateEntityID(field, value string) error {
	for _, r := range value {
		if r == '"' || r == '\\' || unicode.IsControl(r) {
			return &ValidationError{Field: field, Value: value, Rule: "contains a character that cannot be represented safely"}
		}
	}
	return nil
}

func validateAttributeName(field, value string) error {
	if value == "" {
		return &ValidationError{Field: field, Rule: "attribute name must not be empty"}
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return &ValidationError{Field: field, Value: value, Rule: "attribute name contains a control character"}
		}
	}
	return nil
}

func validateRequestID(value string) error {
	if value == "" {
		return &ValidationError{Field: "request ID", Rule: "must be non-empty and safe for correlation"}
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return &ValidationError{Field: "request ID", Rule: "must not contain control characters"}
		}
	}
	return nil
}

func validateIP(value string) error {
	if net.ParseIP(value) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return nil
	}
	return &ValidationError{Field: "IP attribute", Value: value, Rule: "must be an IP address or CIDR network"}
}

func asciiLetterOrUnderscore(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func asciiLetterDigitOrUnderscore(b byte) bool {
	return asciiLetterOrUnderscore(b) || b >= '0' && b <= '9'
}
