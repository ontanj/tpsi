package tpsi

import (
    "math/big"
)

type cryptosystem interface {
    Encrypt(plaintext *big.Int) (*big.Int, error)
    EncryptFixed(plaintext *big.Int, randomizer *big.Int) (*big.Int, error)
    CombinePartials([]partial_decryption) (*big.Int, error)
    Add(...*big.Int) (*big.Int, error)
    MultiplyScalar(ciphertext *big.Int, constant *big.Int) (*big.Int, error)
    MultiplyScalarFixed(ciphertext *big.Int, constant *big.Int, randomizer *big.Int) (*big.Int, error)
    Multiply(*big.Int, *big.Int) (*big.Int, error)
    N() *big.Int // size of plaintext space
}

type secret_key interface {
    PartialDecrypt(*big.Int) (partial_decryption, error)
}

type partial_decryption interface {}

