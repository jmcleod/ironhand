package key

// Rotatable can have its encryption rotated from one key to another.
type Rotatable interface {
	Rotate(Decrypter, Encrypter) error
}
