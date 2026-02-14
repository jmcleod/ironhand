package vault

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateID(t *testing.T) {
	t.Run("valid IDs", func(t *testing.T) {
		assert.NoError(t, validateID("abc", "test"))
		assert.NoError(t, validateID("item-123", "test"))
		assert.NoError(t, validateID("my_vault_id", "test"))
		assert.NoError(t, validateID("abc123", "test"))
	})

	t.Run("empty", func(t *testing.T) {
		err := validateID("", "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must not be empty")
	})

	t.Run("too long", func(t *testing.T) {
		long := strings.Repeat("a", MaxIDLength+1)
		err := validateID(long, "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum length")
	})

	t.Run("contains colon", func(t *testing.T) {
		err := validateID("foo:bar", "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "forbidden character")
	})

	t.Run("contains slash", func(t *testing.T) {
		err := validateID("foo/bar", "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "forbidden character")
	})

	t.Run("contains control char", func(t *testing.T) {
		err := validateID("foo\x00bar", "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "control character")
	})
}

func TestValidateFieldName(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, validateFieldName("username"))
		assert.NoError(t, validateFieldName("password"))
		assert.NoError(t, validateFieldName("_name"))
	})

	t.Run("empty", func(t *testing.T) {
		err := validateFieldName("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must not be empty")
	})

	t.Run("too long", func(t *testing.T) {
		long := strings.Repeat("a", MaxFieldNameLength+1)
		err := validateFieldName(long)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum length")
	})

	t.Run("contains colon", func(t *testing.T) {
		err := validateFieldName("bad:name")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "forbidden character")
	})

	t.Run("control char", func(t *testing.T) {
		err := validateFieldName("bad\x00name")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "control character")
	})
}

func TestValidateFields(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, validateFields(Fields{"username": []byte("admin"), "password": []byte("secret")}))
	})

	t.Run("empty", func(t *testing.T) {
		err := validateFields(Fields{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one field")
	})

	t.Run("too many fields", func(t *testing.T) {
		fields := make(Fields, MaxFieldCount+1)
		for i := range MaxFieldCount + 1 {
			fields[strings.Repeat("a", 1)+string(rune('a'+i%26))+strings.Repeat("b", i)] = []byte("v")
		}
		err := validateFields(fields)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("field too large", func(t *testing.T) {
		err := validateFields(Fields{"big": make([]byte, MaxFieldSize+1)})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})
}
