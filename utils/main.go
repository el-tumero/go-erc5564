package utils

import (
	"crypto/sha256"
	"math/big"
)

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
