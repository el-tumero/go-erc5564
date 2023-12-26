package stealth

import (
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type PubKey struct {
	X *big.Int
	Y *big.Int
}

type KeyPair struct {
	Private []byte
	Public  PubKey
}

func GenerateKeyPair() *KeyPair {
	token := make([]byte, 32)
	rand.Read(token)
	x, y := secp256k1.S256().ScalarBaseMult(token)

	return &KeyPair{
		Private: token,
		Public: PubKey{
			X: x,
			Y: y,
		},
	}
}
