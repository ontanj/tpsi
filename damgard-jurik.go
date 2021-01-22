
package tpsi

import (
	"math/big"
    "github.com/niclabs/tcpaillier"
    gm "github.com/ontanj/generic-matrix"
)

type DJ_encryption struct {
    gm.DJ_public_key
}

func (pk DJ_encryption) Add(a, b Ciphertext) (sum Ciphertext, err error) {
    return pk.PubKey.Add(a.(*big.Int), b.(*big.Int))
}

func (pk DJ_encryption) Scale(cipher Ciphertext, factor *big.Int) (Ciphertext, error) {
    prod, _, err := pk.PubKey.Multiply(cipher.(*big.Int), factor)
    return prod, err
}

func (pk DJ_encryption) Encrypt(plaintext *big.Int) (ciphertext Ciphertext, err error) {
    ciphertext, _, err = pk.PubKey.Encrypt(plaintext)
    return
}

func (pk DJ_encryption) CombinePartials(parts []Partial_decryption) (plaintext *big.Int, err error) { 
    casted_parts := make([]*tcpaillier.DecryptionShare, len(parts))
    for i, p := range parts {
        casted_parts[i] = p.(*tcpaillier.DecryptionShare)
    }
    return pk.CombineShares(casted_parts...)
}

func (pk DJ_encryption) EvaluationSpace() gm.Space {
    return pk.DJ_public_key
}

func (pk DJ_encryption) N() *big.Int {
    return pk.DJ_public_key.PubKey.N
}

type DJ_secret_key struct {
    *tcpaillier.KeyShare
}

func (sk DJ_secret_key) PartialDecrypt(ciphertext Ciphertext) (Partial_decryption, error) {
    return sk.KeyShare.PartialDecrypt(ciphertext.(*big.Int))
}

type DJ_ds struct {
    *tcpaillier.DecryptionShare
}

func NewDJCryptosystem(n int) (cryptosystem DJ_encryption, secret_keys []DJ_secret_key, err error) {
    return NewCustomDJCryptosystem(n, 512, 1)
}

func NewCustomDJCryptosystem(n, bitSize, s int) (cryptosystem DJ_encryption, secret_keys []DJ_secret_key, err error) {
    tcsks, tcpk, err := tcpaillier.NewKey(bitSize, uint8(s), uint8(n), uint8(n))
    if err != nil {return}
    cryptosystem = DJ_encryption{gm.DJ_public_key{PubKey: tcpk}}
    secret_keys = make([]DJ_secret_key, n)
    for i, tcsk := range tcsks {
        secret_keys[i] = DJ_secret_key{tcsk}
    }
    return
}