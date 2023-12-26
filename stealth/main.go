package stealth

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/el-tumero/go-erc5564/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func GenerateStealthAddress(stealthMetaAddress string) (common.Address, *PubKey, byte, error) {
	// generate a random 32-byte entropy ephemeral private key
	ephemeralKeyPair := GenerateKeyPair()

	// parse the spending and viewing public keys
	spendingPubKey, viewingPubKey, err := GetKeysFromMetaAddress(stealthMetaAddress)
	if err != nil {
		return common.Address{}, nil, 0, err
	}

	// computing shared secret
	x, y := secp256k1.S256().ScalarMult(viewingPubKey.X, viewingPubKey.Y, ephemeralKeyPair.Private)

	// the secret is hashed
	sh, err := utils.HashCurvePoints(x, y)
	if err != nil {
		return common.Address{}, nil, 0, err
	}

	// the view tag is extracted by taking the most significant byte of sh
	v := sh[0]

	// multiply the hashed shared secret with the generator point
	sx, sy := secp256k1.S256().ScalarBaseMult(sh)

	// the recipient’s stealth public key is computed
	stealthPubX, stealthPubY := secp256k1.S256().Add(spendingPubKey.X, spendingPubKey.Y, sx, sy)

	// the recipient’s stealth address
	stealthPubkey := ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     stealthPubX,
		Y:     stealthPubY,
	}
	stealthAddress := crypto.PubkeyToAddress(stealthPubkey)

	return stealthAddress, &ephemeralKeyPair.Public, v, nil
}

func CheckStealthAddress(stealthAddress common.Address, ephemeralPubKey *PubKey, viewingKey []byte, spendingPubKey *PubKey, viewTag byte) (bool, error) {
	// shared secret is computed by multiplying the viewing private key with the ephemeral public key of the announcement
	x, y := secp256k1.S256().ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, viewingKey)

	// the secret is hashed
	sh, err := utils.HashCurvePoints(x, y)
	if err != nil {
		return false, err
	}

	// the view tag is extracted by taking the most significant byte and can be compared to the given view tag
	if sh[0] != viewTag {
		return false, nil
	}

	// multiply the hashed shared secret with the generator point
	sx, sy := secp256k1.S256().ScalarBaseMult(sh)

	// the stealth public key is computed
	stealthPubX, stealthPubY := secp256k1.S256().Add(spendingPubKey.X, spendingPubKey.Y, sx, sy)

	// the derived stealth address is computed
	stealthPubkey := ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     stealthPubX,
		Y:     stealthPubY,
	}
	derivedStealthAddress := crypto.PubkeyToAddress(stealthPubkey)
	if derivedStealthAddress.Cmp(stealthAddress) != 0 {
		return false, nil
	}

	return true, nil
}

func ComputeStealthKey(stealthAddress common.Address, ephemeralPubKey *PubKey, viewingKey []byte, spendingKey []byte) ([]byte, error) {
	// shared secret is computed by multiplying the viewing private key with the ephemeral public key of the announcement
	x, y := secp256k1.S256().ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, viewingKey)

	// the secret is hashed
	sh, err := utils.HashCurvePoints(x, y)
	if err != nil {
		return nil, err
	}

	// the stealth private key is computed
	shi := big.NewInt(0).SetBytes(sh)
	ski := big.NewInt(0).SetBytes(spendingKey)

	add := big.NewInt(0).Add(shi, ski)
	mod := big.NewInt(0).Mod(add, secp256k1.S256().N)

	// generate stealth address
	stealthPubX, stealthPubY := secp256k1.S256().ScalarBaseMult(mod.Bytes())
	stealthPubkey := ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     stealthPubX,
		Y:     stealthPubY,
	}
	derivedStealthAddress := crypto.PubkeyToAddress(stealthPubkey)
	if derivedStealthAddress.Cmp(stealthAddress) != 0 {
		return nil, fmt.Errorf("addresses not equal")
	}

	return mod.Bytes(), nil
}
