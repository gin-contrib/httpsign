package crypto

// Crypto interface for signing algorithm
type Crypto interface {
	Name() string
	Sign(msg, secret string) ([]byte, error)
}
