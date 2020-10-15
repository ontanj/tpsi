package tpsi

import (
    "github.com/niclabs/tcpaillier"
)

// generate n key shares of bitSize and one public key, using parameter s (where e.g. s = 1)
func GenerateKeys(bitSize, s, n int) ([]*tcpaillier.KeyShare, *tcpaillier.PubKey, error) {
	return tcpaillier.NewKey(bitSize, uint8(s), uint8(n), uint8(n))
}

