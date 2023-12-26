package stealth

import (
	"github.com/el-tumero/go-erc5564/utils"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

const STEALTH_META_PREFIX = "st:eth:0x"

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
	metaAddress = append(metaAddress, []byte(STEALTH_META_PREFIX)...)
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

	spendingPubKeyComp, err := hexutil.Decode(string(utils.AddEip55Prefix(spendingPart)))
	if err != nil {
		return nil, nil, err
	}

	viewingPubKeyComp, err := hexutil.Decode(string(utils.AddEip55Prefix(viewingPart)))
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
