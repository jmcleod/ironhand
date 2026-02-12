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

func TestValidateContentType(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, validateContentType("text/plain"))
		assert.NoError(t, validateContentType("application/json"))
		assert.NoError(t, validateContentType("application/octet-stream"))
	})

	t.Run("empty", func(t *testing.T) {
		err := validateContentType("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must not be empty")
	})

	t.Run("too long", func(t *testing.T) {
		long := "text/" + strings.Repeat("a", MaxContentTypeLength)
		err := validateContentType(long)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum length")
	})

	t.Run("no slash", func(t *testing.T) {
		err := validateContentType("plaintext")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MIME format")
	})

	t.Run("control char", func(t *testing.T) {
		err := validateContentType("text/\x01plain")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "control character")
	})
}

func TestValidateContentSize(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		assert.NoError(t, validateContentSize(make([]byte, MaxContentSize)))
	})

	t.Run("exceeds limit", func(t *testing.T) {
		err := validateContentSize(make([]byte, MaxContentSize+1))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})
}
