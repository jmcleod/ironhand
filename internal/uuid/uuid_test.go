package uuid

import (
	"testing"
)

func TestNew(t *testing.T) {
	id1 := New()
	id2 := New()

	if len(id1) == 0 {
		t.Error("UUID should not be empty")
	}

	if id1 == id2 {
		t.Error("UUIDs should be unique")
	}
}
