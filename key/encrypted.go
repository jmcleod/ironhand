package key

// Encrypted represents a piece of data that has been encrypted by a specific key.
type Encrypted interface {
	ID() string
	EncryptedBy() string
	Decrypter(Decrypter) (Decrypter, error)
}
