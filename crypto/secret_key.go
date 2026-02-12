package crypto

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jmcleod/ironhand/internal/util"
)

const (
	secretKeyVersion = 1
	secretKeyIDLen   = 6
	secretLength     = 26
)

var secretKeyRE = regexp.MustCompile(`^V(\d)-([A-Za-z0-9]{6})-([A-Za-z0-9]{6})-([A-Za-z0-9]{5})-([A-Za-z0-9]{5})-([A-Za-z0-9]{5})-([A-Za-z0-9]{5})$`)

// SecretKey represents a versioned, formatted secret key used as one
// of the two inputs to the MUK derivation scheme.
type SecretKey interface {
	fmt.Stringer
	Version() int
	ID() string
	Bytes() []byte
}

type secretKey struct {
	version int
	id      string
	secret  []byte
}

func (s *secretKey) String() string {
	secretStr := string(s.secret)
	return fmt.Sprintf("V%d-%s-%s-%s-%s-%s-%s",
		s.version, s.id,
		secretStr[0:6], secretStr[6:11], secretStr[11:16],
		secretStr[16:21], secretStr[21:26])
}

func (s *secretKey) Version() int {
	return s.version
}

func (s *secretKey) ID() string {
	return s.id
}

func (s *secretKey) Bytes() []byte {
	return util.CopyBytes(s.secret)
}

// ParseSecretKey parses a secret key from its formatted string representation.
func ParseSecretKey(str string) (SecretKey, error) {
	matches := secretKeyRE.FindStringSubmatch(str)
	if matches == nil {
		return nil, fmt.Errorf("%s is an invalid secret key format", str)
	}

	version, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, fmt.Errorf("parsing version: %w", err)
	}
	id := matches[2]
	secret := strings.Join(matches[3:], "")

	return &secretKey{
		version: version,
		id:      id,
		secret:  []byte(secret),
	}, nil
}

// NewSecretKey generates a new random secret key.
func NewSecretKey() (SecretKey, error) {
	id, err := util.RandomChars(secretKeyIDLen)
	if err != nil {
		return nil, fmt.Errorf("generating secret key ID: %w", err)
	}
	secret, err := util.RandomChars(secretLength)
	if err != nil {
		return nil, fmt.Errorf("generating secret key material: %w", err)
	}
	return &secretKey{
		version: secretKeyVersion,
		id:      id,
		secret:  []byte(secret),
	}, nil
}
