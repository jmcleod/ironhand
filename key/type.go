// Package key provides symmetric key management with encryption, decryption,
// key wrapping, rotation, and JSON serialization.
package key

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Type represents the key type.
type Type int

const (
	Symmetric Type = 0
)

// ErrUnknownType is returned when an unrecognized key type is encountered.
var ErrUnknownType = errors.New("unknown key type")

func (t Type) String() string {
	switch t {
	case Symmetric:
		return "Symmetric"
	default:
		return "Unknown"
	}
}

func (t *Type) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("unmarshaling key type: %w", err)
	}

	switch s {
	case "Symmetric":
		*t = Symmetric
	default:
		return ErrUnknownType
	}

	return nil
}

func (t Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
