package httpsign

import "github.com/gin-contrib/httpsign/crypto"

// KeyID define type
type KeyID string

// Secret define secret key and algorithm that key use
type Secret struct {
	Key       string
	Algorithm crypto.Crypto
}

// Secrets map with keyID and secret
type Secrets map[KeyID]*Secret
