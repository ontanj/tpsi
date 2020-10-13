package tpsi

import (
    "github.com/niclabs/tcpaillier"
)

// generate n key shares of bitSize and one public key, using parameter s (where e.g. s = 1)
func GenerateKeys(bitSize int, s, n uint8) ([]*tcpaillier.KeyShare, *tcpaillier.PubKey, error) {
	return tcpaillier.NewKey(bitSize, s, n, n)
}

