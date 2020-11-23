
package tpsi

import (
	"math/big"
	"github.com/niclabs/tcpaillier"
)

type dj_pk struct {
    *tcpaillier.PubKey
}

func (pk dj_pk) Encrypt(plaintext *big.Int) (ciphertext *big.Int, err error) {
    ciphertext, _, err = pk.PubKey.Encrypt(plaintext)
    return
}

func (pk dj_pk) EncryptFixed(plaintext, randomizer *big.Int) (ciphertext *big.Int, err error) {
    return pk.PubKey.EncryptFixed(plaintext, randomizer)
}

func (pk dj_pk) CombinePartials(parts []partial_decryption) (plaintext *big.Int, err error) { 
    casted_parts := make([]*tcpaillier.DecryptionShare, len(parts))
    for i, p := range parts {
        casted_parts[i] = p.(*tcpaillier.DecryptionShare)
    }
    return pk.CombineShares(casted_parts...)
}

func (pk dj_pk) Add(terms ...*big.Int) (sum *big.Int, err error) {
    return pk.PubKey.Add(terms...)
}

func (pk dj_pk) MultiplyScalar(ciphertext, constant *big.Int) (product *big.Int, err error) {
    product, _, err = pk.PubKey.Multiply(ciphertext, constant)
    return
}

func (pk dj_pk) MultiplyScalarFixed(ciphertext, constant, randomizer *big.Int) (product *big.Int, err error) {
    return pk.PubKey.MultiplyFixed(ciphertext, constant, randomizer)
}

func (pk dj_pk) Multiply(a, b *big.Int) (*big.Int, error) {
    panic("Not supported for Damgård-Jurik cryptosystem.")
}

func (pk dj_pk) N() *big.Int {
    return pk.PubKey.N
}

type dj_sk struct {
    *tcpaillier.KeyShare
}

func (sk dj_sk) PartialDecrypt(ciphertext *big.Int) (partial_decryption, error) {
    return sk.KeyShare.PartialDecrypt(ciphertext)
}

func ConvertDJSKSlice(sks_in []dj_sk) []secret_key {
    sks_out := make([]secret_key, len(sks_in))
    for i, val := range sks_in {
        sks_out[i] = secret_key(val)
    }
    return sks_out
}

type dj_ds struct {
    *tcpaillier.DecryptionShare
}

func NewDJCryptosystem(bitSize, n int) (cryptosystem dj_pk, secret_keys []dj_sk, err error) {
    tcsks, tcpk, err := GenerateKeys(bitSize, 1, n)
    if err != nil {return}
    cryptosystem = dj_pk{tcpk}
    secret_keys = make([]dj_sk, n)
    for i, tcsk := range tcsks {
        secret_keys[i] = dj_sk{tcsk}
    }
    return
}