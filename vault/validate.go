package vault

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

func validateID(id, label string) error {
	if id == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if len(id) > MaxIDLength {
		return fmt.Errorf("%s exceeds maximum length of %d", label, MaxIDLength)
	}
	if !utf8.ValidString(id) {
		return fmt.Errorf("%s contains invalid UTF-8", label)
	}
	for _, r := range id {
		if r == ':' || r == '/' {
			return fmt.Errorf("%s contains forbidden character %q", label, r)
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control character", label)
		}
	}
	return nil
}

func validateContentType(ct string) error {
	if ct == "" {
		return fmt.Errorf("content type must not be empty")
	}
	if len(ct) > MaxContentTypeLength {
		return fmt.Errorf("content type exceeds maximum length of %d", MaxContentTypeLength)
	}
	hasSlash := false
	for _, r := range ct {
		if r == '/' {
			hasSlash = true
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("content type contains control character")
		}
	}
	if !hasSlash {
		return fmt.Errorf("content type must contain '/' (MIME format)")
	}
	return nil
}

func validateContentSize(data []byte) error {
	if len(data) > MaxContentSize {
		return fmt.Errorf("content size %d exceeds maximum of %d bytes", len(data), MaxContentSize)
	}
	return nil
}

func validateRole(role MemberRole) error {
	switch role {
	case RoleOwner, RoleWriter, RoleReader:
		return nil
	default:
		return fmt.Errorf("invalid member role %q", role)
	}
}
