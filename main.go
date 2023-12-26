package main

import (
	"fmt"

	"github.com/el-tumero/go-erc5564/stealth"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func main() {
	// repeipient
	metaAddr, spendingPrivKey, viewingPrivKey, err := stealth.GenerateMetaAddress()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("metaAddress", metaAddr)

	// sender
	stealthAddress, ephemeralPubKey, viewTag, err := stealth.GenerateStealthAddress(metaAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	// receipient
	spendingPubKey, _, err := stealth.GetKeysFromMetaAddress(metaAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	res, _ := stealth.CheckStealthAddress(stealthAddress, ephemeralPubKey, viewingPrivKey, spendingPubKey, viewTag)
	fmt.Println("owner of this stealth address", res)

	fmt.Println("stealthAddress", stealthAddress)

	stealthPrivKey, err := stealth.ComputeStealthKey(stealthAddress, ephemeralPubKey, viewingPrivKey, spendingPrivKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("stealthPrivateKey", hexutil.Encode(stealthPrivKey))
}
