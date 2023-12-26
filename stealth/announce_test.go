package stealth_test

import (
	"math/big"
	"testing"

	"github.com/el-tumero/go-erc5564/stealth"
	"github.com/ethereum/go-ethereum/common"
)

func TestBigIntBytes(t *testing.T) {
	buf := make([]byte, 32)
	big.NewInt(0xffffffffffffe).FillBytes(buf)
	t.Log(buf)

	if len(buf) != 32 {
		t.FailNow()
	}
}

func TestGenerateSendEthMetadata(t *testing.T) {
	metadata := stealth.GenerateSendEthMetadata(54, big.NewInt(542))
	t.Log("metadata", metadata)

	if len(metadata) != 57 {
		t.FailNow()
	}
}

func TestGenerateSendTokenMetadata(t *testing.T) {
	hexAddr := "0x21BbDf979CE87886641a7875D2C7F26513D39542"
	addr := common.HexToAddress(hexAddr)
	metadata := stealth.GenerateSendTokenMetadata(54, []byte{0xf, 0x1, 0xf, 0x1}, addr.Bytes(), big.NewInt(542))
	t.Log("metadata", metadata)

	if len(metadata) != 57 {
		t.FailNow()
	}
}
