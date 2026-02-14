package vault

import (
	"unicode"
	"unicode/utf8"
)

func validateID(id, label string) error {
	if id == "" {
		return validationErrorf("%s must not be empty", label)
	}
	if len(id) > MaxIDLength {
		return validationErrorf("%s exceeds maximum length of %d", label, MaxIDLength)
	}
	if !utf8.ValidString(id) {
		return validationErrorf("%s contains invalid UTF-8", label)
	}
	for _, r := range id {
		if r == ':' || r == '/' {
			return validationErrorf("%s contains forbidden character %q", label, r)
		}
		if unicode.IsControl(r) {
			return validationErrorf("%s contains control character", label)
		}
	}
	return nil
}

func validateContentType(ct string) error {
	if ct == "" {
		return validationErrorf("content type must not be empty")
	}
	if len(ct) > MaxContentTypeLength {
		return validationErrorf("content type exceeds maximum length of %d", MaxContentTypeLength)
	}
	hasSlash := false
	for _, r := range ct {
		if r == '/' {
			hasSlash = true
		}
		if unicode.IsControl(r) {
			return validationErrorf("content type contains control character")
		}
	}
	if !hasSlash {
		return validationErrorf("content type must contain '/' (MIME format)")
	}
	return nil
}

func validateContentSize(data []byte) error {
	if len(data) > MaxContentSize {
		return validationErrorf("content size %d exceeds maximum of %d bytes", len(data), MaxContentSize)
	}
	return nil
}

func validateRole(role MemberRole) error {
	switch role {
	case RoleOwner, RoleWriter, RoleReader:
		return nil
	default:
		return validationErrorf("invalid member role %q", role)
	}
}
