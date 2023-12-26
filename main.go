package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

const STEALTH_PREFIX = "st:eth:0x"

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

func GenerateMetaAddress() (string, []byte, []byte, error) {
	spendingKeyPair := GenerateKeyPair()
	viewingKeyPair := GenerateKeyPair()

	spendingPubKeyComp := secp256k1.CompressPubkey(spendingKeyPair.Public.X, spendingKeyPair.Public.Y)
	viewingPubKeyComp := secp256k1.CompressPubkey(viewingKeyPair.Public.X, viewingKeyPair.Public.Y)

	spendingPubKeyHex := hexutil.Encode(spendingPubKeyComp)
	viewingPubKeyHex := hexutil.Encode(viewingPubKeyComp)

	// st:eth:0x = 9
	// 9 + 66 + 66 = 141
	metaAddress := make([]byte, 0, 141)
	metaAddress = append(metaAddress, []byte(STEALTH_PREFIX)...)
	metaAddress = append(metaAddress, spendingPubKeyHex[2:]...)
	metaAddress = append(metaAddress, viewingPubKeyHex[2:]...)

	output := string(metaAddress)

	return output, spendingKeyPair.Private, viewingKeyPair.Private, nil
}

func GetKeysFromMetaAddress(metaAddress string) (*PubKey, *PubKey, error) {
	// split
	meta := []byte(metaAddress)
	spendingPart := meta[9:75]
	viewingPart := meta[75:141]

	spendingPubKeyComp, err := hexutil.Decode(string(AddEip55Prefix(spendingPart)))
	if err != nil {
		return nil, nil, err
	}

	viewingPubKeyComp, err := hexutil.Decode(string(AddEip55Prefix(viewingPart)))
	if err != nil {
		return nil, nil, err
	}

	xs, ys := secp256k1.DecompressPubkey(spendingPubKeyComp)
	if err != nil {
		return nil, nil, err
	}

	xv, yv := secp256k1.DecompressPubkey(viewingPubKeyComp)
	if err != nil {
		return nil, nil, err
	}

	return &PubKey{X: xs, Y: ys}, &PubKey{X: xv, Y: yv}, nil
}

func AddEip55Prefix(hex []byte) []byte {
	return append([]byte{'0', 'x'}, hex...)
}

func HashCurvePoints(x *big.Int, y *big.Int) ([]byte, error) {
	h := sha256.New()
	_, err := h.Write(x.Bytes())
	if err != nil {
		return nil, err
	}
	_, err = h.Write(y.Bytes())
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

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
	sh, err := HashCurvePoints(x, y)
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
	sh, err := HashCurvePoints(x, y)
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
	sh, err := HashCurvePoints(x, y)
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

func main() {
	// repeipient
	metaAddr, spendingPrivKey, viewingPrivKey, err := GenerateMetaAddress()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("metaAddress", metaAddr)

	// sender
	stealthAddress, ephemeralPubKey, viewTag, err := GenerateStealthAddress(metaAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	// receipient
	spendingPubKey, _, err := GetKeysFromMetaAddress(metaAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	res, _ := CheckStealthAddress(stealthAddress, ephemeralPubKey, viewingPrivKey, spendingPubKey, viewTag)
	fmt.Println("owner of this stealth address", res)

	fmt.Println("stealthAddress", stealthAddress)

	stealthPrivKey, err := ComputeStealthKey(stealthAddress, ephemeralPubKey, viewingPrivKey, spendingPrivKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("stealthPrivateKey", hexutil.Encode(stealthPrivKey))
}
