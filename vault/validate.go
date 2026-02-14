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

func validateFieldName(name string) error {
	if name == "" {
		return validationErrorf("field name must not be empty")
	}
	if len(name) > MaxFieldNameLength {
		return validationErrorf("field name exceeds maximum length of %d", MaxFieldNameLength)
	}
	if !utf8.ValidString(name) {
		return validationErrorf("field name contains invalid UTF-8")
	}
	for _, r := range name {
		if r == ':' || r == '/' {
			return validationErrorf("field name contains forbidden character %q", r)
		}
		if unicode.IsControl(r) {
			return validationErrorf("field name contains control character")
		}
	}
	return nil
}

func validateFields(fields Fields) error {
	if len(fields) == 0 {
		return validationErrorf("item must have at least one field")
	}
	if len(fields) > MaxFieldCount {
		return validationErrorf("field count %d exceeds maximum of %d", len(fields), MaxFieldCount)
	}
	for name, value := range fields {
		if err := validateFieldName(name); err != nil {
			return err
		}
		if len(value) > MaxFieldSize {
			return validationErrorf("field %q size %d exceeds maximum of %d bytes", name, len(value), MaxFieldSize)
		}
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
