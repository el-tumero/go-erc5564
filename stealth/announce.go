package stealth

import "math/big"

func GenerateSendEthMetadata(viewTag byte, amount *big.Int) []byte {
	output := []byte{viewTag, 0xe, 0xe, 0xe, 0xe,
		0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe,
		0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe,
	}
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)
	output = append(output, amountBytes...)
	return output
}

func GenerateSendTokenMetadata(viewTag byte, functionIdentifier []byte, tokenAddress []byte, amount *big.Int) []byte {
	if len(functionIdentifier) != 4 || len(tokenAddress) != 20 {
		return nil
	}
	output := []byte{viewTag}
	output = append(output, functionIdentifier...)
	output = append(output, tokenAddress...)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)
	output = append(output, amountBytes...)
	return output
}
